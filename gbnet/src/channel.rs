//! Message channels with 5 LiteNetLib-style delivery modes.
//!
//! Each [`Channel`] provides independent message buffering and delivery
//! guarantees: Unreliable, UnreliableSequenced, ReliableUnordered,
//! ReliableOrdered, and ReliableSequenced.
use crate::config::{ChannelConfig, DeliveryMode};
use crate::stats::ChannelStats;
use crate::util::sequence_greater_than;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Errors from channel send operations.
#[derive(Debug)]
pub enum ChannelError {
    BufferFull,
    MessageTooLarge,
    InvalidSequence,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::BufferFull => write!(f, "Channel buffer full"),
            ChannelError::MessageTooLarge => write!(f, "Message too large for channel"),
            ChannelError::InvalidSequence => write!(f, "Invalid sequence number"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// Wire format for channel messages: [u16 sequence][payload]
const SEQUENCE_BYTES: usize = 2;
use crate::config::MAX_BACKOFF_EXPONENT;

/// A message queued for sending on a channel, with reliability metadata.
#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub sequence: u16,
    pub data: Vec<u8>,
    pub send_time: Option<Instant>,
    pub acked: bool,
    pub retry_count: u32,
    pub reliable: bool,
}

/// A message channel providing one of 5 delivery modes with independent buffering.
#[derive(Debug)]
pub struct Channel {
    id: u8,
    config: ChannelConfig,

    send_sequence: u16,
    send_buffer: VecDeque<ChannelMessage>,
    pending_ack: HashMap<u16, ChannelMessage>,

    receive_sequence: u16,
    last_received_sequence: u16,
    ordered_receive_buffer: HashMap<u16, (Vec<u8>, Instant)>,
    delivery_queue: VecDeque<Vec<u8>>,

    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    gap_sequences_skipped: u64,
    messages_dropped: u64,
}

impl Channel {
    pub fn new(id: u8, config: ChannelConfig) -> Self {
        Self {
            id,
            config,
            send_sequence: 0,
            send_buffer: VecDeque::new(),
            pending_ack: HashMap::new(),
            receive_sequence: 0,
            last_received_sequence: 0,
            ordered_receive_buffer: HashMap::new(),
            delivery_queue: VecDeque::new(),
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            gap_sequences_skipped: 0,
            messages_dropped: 0,
        }
    }

    /// Queue a message for sending on this channel.
    /// The `reliable` parameter allows per-message reliability override:
    /// - On an unreliable channel with `reliable=true`, the message is tracked for ACK/retransmit.
    /// - On a reliable channel with `reliable=false`, the message is sent fire-and-forget.
    pub fn send(&mut self, data: &[u8], reliable: bool) -> Result<(), ChannelError> {
        if data.len() > self.config.max_message_size {
            return Err(ChannelError::MessageTooLarge);
        }

        if self.send_buffer.len() >= self.config.message_buffer_size {
            if self.config.block_on_full {
                return Err(ChannelError::BufferFull);
            } else {
                self.send_buffer.pop_front();
            }
        }

        let effective_reliable = reliable;
        let message = ChannelMessage {
            sequence: self.send_sequence,
            data: data.to_vec(),
            send_time: None,
            acked: false,
            retry_count: 0,
            reliable: effective_reliable,
        };

        self.send_sequence = self.send_sequence.wrapping_add(1);
        self.send_buffer.push_back(message);
        self.messages_sent += 1;
        self.bytes_sent += data.len() as u64;

        Ok(())
    }

    /// Get the next outgoing message, serialized with sequence header.
    /// For unreliable channels, this pops the message.
    /// For reliable channels, the message stays in pending_ack until acknowledged.
    pub fn get_outgoing_message(&mut self) -> Option<(u16, Vec<u8>)> {
        if let Some(message) = self.send_buffer.pop_front() {
            let seq = message.sequence;
            let mut wire_data = Vec::with_capacity(SEQUENCE_BYTES + message.data.len());
            wire_data.extend_from_slice(&seq.to_be_bytes());
            wire_data.extend_from_slice(&message.data);

            if message.reliable {
                let mut pending = message;
                pending.send_time = Some(Instant::now());
                self.pending_ack.insert(seq, pending);
            }

            Some((seq, wire_data))
        } else {
            None
        }
    }

    /// Get messages that need retransmission (for reliable channels).
    /// Messages exceeding `max_reliable_retries` are removed from pending_ack.
    pub fn get_retransmit_messages(
        &mut self,
        now: Instant,
        rto: std::time::Duration,
    ) -> Vec<(u16, Vec<u8>)> {
        if !self.config.delivery_mode.is_reliable() {
            return Vec::new();
        }

        let max_retries = self.config.max_reliable_retries;
        let mut retransmits = Vec::new();
        let mut expired = Vec::new();
        for (seq, msg) in &mut self.pending_ack {
            if let Some(send_time) = msg.send_time {
                let backoff_rto = rto * (1u32 << msg.retry_count.min(MAX_BACKOFF_EXPONENT));
                if now.duration_since(send_time) >= backoff_rto {
                    if msg.retry_count >= max_retries {
                        expired.push(*seq);
                        continue;
                    }
                    msg.retry_count += 1;
                    msg.send_time = Some(now);

                    let mut wire_data = Vec::with_capacity(SEQUENCE_BYTES + msg.data.len());
                    wire_data.extend_from_slice(&seq.to_be_bytes());
                    wire_data.extend_from_slice(&msg.data);
                    retransmits.push((*seq, wire_data));
                }
            }
        }
        for seq in expired {
            self.pending_ack.remove(&seq);
        }
        retransmits
    }

    /// Process an incoming wire message for this channel.
    /// Wire format: [u16 sequence BE][payload]
    pub fn on_packet_received(&mut self, wire_data: Vec<u8>) {
        if wire_data.len() < SEQUENCE_BYTES {
            self.delivery_queue.push_back(wire_data);
            self.messages_received += 1;
            return;
        }

        let seq = u16::from_be_bytes([wire_data[0], wire_data[1]]);
        let data = wire_data[SEQUENCE_BYTES..].to_vec();

        self.bytes_received += data.len() as u64;

        match self.config.delivery_mode {
            DeliveryMode::Unreliable => {
                self.delivery_queue.push_back(data);
                self.messages_received += 1;
            }
            DeliveryMode::UnreliableSequenced => {
                if sequence_greater_than(seq, self.last_received_sequence)
                    || self.messages_received == 0
                {
                    self.last_received_sequence = seq;
                    self.delivery_queue.push_back(data);
                    self.messages_received += 1;
                }
            }
            DeliveryMode::ReliableUnordered => {
                self.delivery_queue.push_back(data);
                self.messages_received += 1;
            }
            DeliveryMode::ReliableOrdered => {
                if seq == self.receive_sequence {
                    self.delivery_queue.push_back(data);
                    self.messages_received += 1;
                    self.receive_sequence = self.receive_sequence.wrapping_add(1);

                    while let Some((buffered, _)) =
                        self.ordered_receive_buffer.remove(&self.receive_sequence)
                    {
                        self.delivery_queue.push_back(buffered);
                        self.messages_received += 1;
                        self.receive_sequence = self.receive_sequence.wrapping_add(1);
                    }
                } else if sequence_greater_than(seq, self.receive_sequence) {
                    if self.ordered_receive_buffer.len() >= self.config.max_ordered_buffer_size {
                        self.evict_oldest_buffered();
                    }
                    self.ordered_receive_buffer
                        .insert(seq, (data, Instant::now()));
                }
            }
            DeliveryMode::ReliableSequenced => {
                if sequence_greater_than(seq, self.last_received_sequence)
                    || self.messages_received == 0
                {
                    self.last_received_sequence = seq;
                    self.delivery_queue.push_back(data);
                    self.messages_received += 1;
                }
            }
        }
    }

    /// Evict the oldest entry (by insertion time) from the ordered receive buffer.
    /// After eviction, if the evicted entry's sequence equals receive_sequence,
    /// advance past it and deliver any contiguous messages at the front.
    fn evict_oldest_buffered(&mut self) {
        let oldest_seq = self
            .ordered_receive_buffer
            .iter()
            .min_by_key(|(_, (_, t))| *t)
            .map(|(&seq, _)| seq);

        if let Some(evicted_seq) = oldest_seq {
            self.ordered_receive_buffer.remove(&evicted_seq);
            self.gap_sequences_skipped += 1;
            self.messages_dropped += 1;

            // If the evicted entry was what we were waiting for, advance
            if evicted_seq == self.receive_sequence {
                self.receive_sequence = self.receive_sequence.wrapping_add(1);
                // Deliver any now-contiguous messages
                while let Some((buffered, _)) =
                    self.ordered_receive_buffer.remove(&self.receive_sequence)
                {
                    self.delivery_queue.push_back(buffered);
                    self.messages_received += 1;
                    self.receive_sequence = self.receive_sequence.wrapping_add(1);
                }
            }
        }
    }

    /// Acknowledge a sent message (called when ACK is received).
    pub fn acknowledge_message(&mut self, sequence: u16) {
        self.pending_ack.remove(&sequence);
    }

    /// Receive the next delivered message.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        self.delivery_queue.pop_front()
    }

    /// Update the channel state. Checks for ordered buffer timeout.
    pub fn update(&mut self) {
        // Check for ordered buffer timeout (ReliableOrdered only)
        if self.config.delivery_mode == DeliveryMode::ReliableOrdered
            && !self.ordered_receive_buffer.is_empty()
        {
            let timeout = self.config.ordered_buffer_timeout;
            let has_timed_out = self
                .ordered_receive_buffer
                .values()
                .any(|(_, inserted_at)| inserted_at.elapsed() > timeout);
            if has_timed_out {
                self.flush_ordered_buffer();
            }
        }
    }

    /// Find the earliest buffered sequence in circular space.
    fn find_earliest_buffered(&self) -> Option<u16> {
        self.ordered_receive_buffer.keys().copied().reduce(|a, b| {
            if sequence_greater_than(a, b) {
                b
            } else {
                a
            }
        })
    }

    /// Skip the gap in ordered delivery and flush all buffered messages in sequence order.
    fn flush_ordered_buffer(&mut self) {
        if let Some(first_seq) = self.find_earliest_buffered() {
            // Count skipped gap sequences
            let mut seq = self.receive_sequence;
            while seq != first_seq {
                self.gap_sequences_skipped += 1;
                seq = seq.wrapping_add(1);
            }

            // Advance receive_sequence past the gap to the first buffered message
            self.receive_sequence = first_seq;

            // Deliver contiguous buffered messages starting from first_seq
            while let Some((data, _)) = self.ordered_receive_buffer.remove(&self.receive_sequence) {
                self.delivery_queue.push_back(data);
                self.messages_received += 1;
                self.receive_sequence = self.receive_sequence.wrapping_add(1);
            }
        }
    }

    /// Reset the channel state.
    pub fn reset(&mut self) {
        self.send_sequence = 0;
        self.receive_sequence = 0;
        self.last_received_sequence = 0;
        self.send_buffer.clear();
        self.pending_ack.clear();
        self.ordered_receive_buffer.clear();
        self.delivery_queue.clear();
        self.messages_sent = 0;
        self.messages_received = 0;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.gap_sequences_skipped = 0;
        self.messages_dropped = 0;
    }

    pub fn is_reliable(&self) -> bool {
        self.config.delivery_mode.is_reliable()
    }

    pub fn delivery_mode(&self) -> DeliveryMode {
        self.config.delivery_mode
    }

    pub fn id(&self) -> u8 {
        self.id
    }

    pub fn config_priority(&self) -> u8 {
        self.config.priority
    }

    pub fn gap_sequences_skipped(&self) -> u64 {
        self.gap_sequences_skipped
    }

    pub fn stats(&self) -> ChannelStats {
        ChannelStats {
            id: self.id,
            messages_sent: self.messages_sent,
            messages_received: self.messages_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            send_buffer_size: self.send_buffer.len(),
            pending_ack_count: self.pending_ack.len(),
            receive_buffer_size: self.ordered_receive_buffer.len(),
            gap_sequences_skipped: self.gap_sequences_skipped,
            messages_dropped: self.messages_dropped,
        }
    }

    /// Mark a message for fast retransmit by resetting its send_time,
    /// causing it to be retransmitted on the next `get_retransmit_messages()` call.
    pub fn mark_for_fast_retransmit(&mut self, seq: u16) {
        if let Some(msg) = self.pending_ack.get_mut(&seq) {
            msg.send_time = Some(Instant::now() - std::time::Duration::from_secs(60));
        }
    }

    pub fn pending_ack_count(&self) -> usize {
        self.pending_ack.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wire(seq: u16, data: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(2 + data.len());
        wire.extend_from_slice(&seq.to_be_bytes());
        wire.extend_from_slice(data);
        wire
    }

    #[test]
    fn test_unreliable_fire_and_forget() {
        let config = ChannelConfig::unreliable();
        let mut ch = Channel::new(0, config);

        ch.send(b"hello", false).unwrap();
        let (seq, wire) = ch.get_outgoing_message().unwrap();
        assert_eq!(seq, 0);

        // Simulate receive
        ch.on_packet_received(wire);
        assert_eq!(ch.receive().unwrap(), b"hello");
        assert!(ch.receive().is_none());
    }

    #[test]
    fn test_unreliable_sequenced_drops_stale() {
        let config = ChannelConfig::unreliable_sequenced();
        let mut ch = Channel::new(0, config);

        // Receive seq 5, then seq 3 (stale)
        ch.on_packet_received(make_wire(5, b"msg5"));
        ch.on_packet_received(make_wire(3, b"msg3")); // should be dropped
        ch.on_packet_received(make_wire(7, b"msg7"));

        assert_eq!(ch.receive().unwrap(), b"msg5");
        assert_eq!(ch.receive().unwrap(), b"msg7");
        assert!(ch.receive().is_none());
    }

    #[test]
    fn test_reliable_unordered_delivers_immediately() {
        let config = ChannelConfig::reliable_unordered();
        let mut ch = Channel::new(0, config);

        // Out of order delivery
        ch.on_packet_received(make_wire(2, b"msg2"));
        ch.on_packet_received(make_wire(0, b"msg0"));
        ch.on_packet_received(make_wire(1, b"msg1"));

        assert_eq!(ch.receive().unwrap(), b"msg2");
        assert_eq!(ch.receive().unwrap(), b"msg0");
        assert_eq!(ch.receive().unwrap(), b"msg1");
    }

    #[test]
    fn test_reliable_ordered_buffers_and_delivers_in_sequence() {
        let config = ChannelConfig::reliable_ordered();
        let mut ch = Channel::new(0, config);

        // Receive out of order: 1, 2, 0
        ch.on_packet_received(make_wire(1, b"msg1"));
        ch.on_packet_received(make_wire(2, b"msg2"));
        // Nothing delivered yet (waiting for seq 0)
        assert!(ch.receive().is_none());

        // Now deliver seq 0 - should flush 0, 1, 2
        ch.on_packet_received(make_wire(0, b"msg0"));
        assert_eq!(ch.receive().unwrap(), b"msg0");
        assert_eq!(ch.receive().unwrap(), b"msg1");
        assert_eq!(ch.receive().unwrap(), b"msg2");
        assert!(ch.receive().is_none());
    }

    #[test]
    fn test_reliable_sequenced_drops_stale_but_acks() {
        let config = ChannelConfig::reliable_sequenced();
        let mut ch = Channel::new(0, config);

        ch.on_packet_received(make_wire(5, b"msg5"));
        ch.on_packet_received(make_wire(3, b"msg3")); // stale, dropped
        ch.on_packet_received(make_wire(8, b"msg8"));

        assert_eq!(ch.receive().unwrap(), b"msg5");
        assert_eq!(ch.receive().unwrap(), b"msg8");
        assert!(ch.receive().is_none());
    }

    #[test]
    fn test_reliable_pending_ack_tracking() {
        let config = ChannelConfig::reliable_ordered();
        let mut ch = Channel::new(0, config);

        ch.send(b"data1", true).unwrap();
        ch.send(b"data2", true).unwrap();
        let (seq0, _) = ch.get_outgoing_message().unwrap();
        let (seq1, _) = ch.get_outgoing_message().unwrap();
        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
        assert_eq!(ch.pending_ack_count(), 2);

        ch.acknowledge_message(0);
        assert_eq!(ch.pending_ack_count(), 1);
        ch.acknowledge_message(1);
        assert_eq!(ch.pending_ack_count(), 0);
    }

    #[test]
    fn test_channel_buffer_full() {
        let mut config = ChannelConfig::reliable_ordered();
        config.message_buffer_size = 2;
        config.block_on_full = true;
        let mut ch = Channel::new(0, config);

        assert!(ch.send(b"msg1", true).is_ok());
        assert!(ch.send(b"msg2", true).is_ok());
        assert!(matches!(
            ch.send(b"msg3", true),
            Err(ChannelError::BufferFull)
        ));
    }

    #[test]
    fn test_channel_round_trip() {
        let config = ChannelConfig::reliable_ordered();
        let mut sender = Channel::new(0, config);
        let mut receiver = Channel::new(0, config);

        sender.send(b"hello world", true).unwrap();
        let (_seq, wire) = sender.get_outgoing_message().unwrap();

        receiver.on_packet_received(wire);
        assert_eq!(receiver.receive().unwrap(), b"hello world");
    }

    #[test]
    fn test_reliable_ordered_duplicate_rejection() {
        let config = ChannelConfig::reliable_ordered();
        let mut ch = Channel::new(0, config);

        ch.on_packet_received(make_wire(0, b"msg0"));
        ch.on_packet_received(make_wire(0, b"msg0")); // duplicate
        ch.on_packet_received(make_wire(1, b"msg1"));

        assert_eq!(ch.receive().unwrap(), b"msg0");
        assert_eq!(ch.receive().unwrap(), b"msg1");
        assert!(ch.receive().is_none());
    }

    #[test]
    fn test_ordered_wraparound_delivery() {
        let mut config = ChannelConfig::reliable_ordered();
        config.max_ordered_buffer_size = 16;
        let mut ch = Channel::new(0, config);

        // Set receive_sequence near wraparound
        ch.receive_sequence = 65534;

        // Receive messages around wraparound: 65535, 0, 1 (out of order, missing 65534)
        ch.on_packet_received(make_wire(65535, b"msg65535"));
        ch.on_packet_received(make_wire(0, b"msg0"));
        ch.on_packet_received(make_wire(1, b"msg1"));

        // Nothing delivered yet (waiting for 65534)
        assert!(ch.receive().is_none());

        // Now deliver 65534 - should flush all in order
        ch.on_packet_received(make_wire(65534, b"msg65534"));
        assert_eq!(ch.receive().unwrap(), b"msg65534");
        assert_eq!(ch.receive().unwrap(), b"msg65535");
        assert_eq!(ch.receive().unwrap(), b"msg0");
        assert_eq!(ch.receive().unwrap(), b"msg1");
        assert!(ch.receive().is_none());
    }

    #[test]
    fn test_ordered_buffer_full_eviction() {
        let mut config = ChannelConfig::reliable_ordered();
        config.max_ordered_buffer_size = 3;
        let mut ch = Channel::new(0, config);

        // Buffer messages 1, 2, 3 (waiting for 0)
        ch.on_packet_received(make_wire(1, b"msg1"));
        ch.on_packet_received(make_wire(2, b"msg2"));
        ch.on_packet_received(make_wire(3, b"msg3"));
        assert_eq!(ch.ordered_receive_buffer.len(), 3);

        // Buffer full, receiving msg 4 should evict oldest
        ch.on_packet_received(make_wire(4, b"msg4"));
        // Should have evicted one entry, buffer still at max
        assert!(ch.ordered_receive_buffer.len() <= 3);
        assert!(ch.gap_sequences_skipped > 0);
    }

    #[test]
    fn test_flush_ordered_buffer_wraparound() {
        let mut config = ChannelConfig::reliable_ordered();
        config.ordered_buffer_timeout = std::time::Duration::from_millis(1);
        let mut ch = Channel::new(0, config);

        // Set receive_sequence near wraparound
        ch.receive_sequence = 65534;

        // Buffer 65535 and 0 (skipping 65534)
        ch.on_packet_received(make_wire(65535, b"a"));
        ch.on_packet_received(make_wire(0, b"b"));

        // Wait for timeout and flush
        std::thread::sleep(std::time::Duration::from_millis(5));
        ch.update();

        // Should have flushed from 65535 (earliest in circular space)
        assert_eq!(ch.receive().unwrap(), b"a");
        assert_eq!(ch.receive().unwrap(), b"b");
        assert!(ch.receive().is_none());
    }
}
