//! Reliable packet delivery with Jacobson/Karels RTT estimation, adaptive RTO,
//! fast retransmit, and bounded in-flight tracking.
use crate::stats::ReliabilityStats;
use crate::util::{sequence_diff, sequence_greater_than};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Result of processing ACKs: (acked channel pairs, fast retransmit candidates).
pub type AckResult = (SmallVec<[(u8, u16); 8]>, SmallVec<[(u8, u16); 4]>);

pub const INITIAL_RTO_MILLIS: u64 = 100;
pub const ACK_BITS_WINDOW: u16 = 64;
pub const RTT_ALPHA: f64 = 0.125;
pub const RTT_BETA: f64 = 0.25;
pub const MIN_RTO_MS: f64 = 50.0;
pub const MAX_RTO_MS: f64 = 2000.0;
const LOSS_WINDOW_SIZE: usize = 256;
pub const FAST_RETRANSMIT_THRESHOLD: u8 = 3;

/// Tracks sent packets for reliability and acknowledgment.
#[derive(Debug)]
pub struct ReliableEndpoint {
    local_sequence: u16,
    remote_sequence: u16,
    ack_bits: u64,

    sent_packets: HashMap<u16, SentPacketRecord>,
    received_packets: SequenceBuffer<bool>,

    max_sequence_distance: u16,
    max_in_flight: usize,

    srtt: f64,
    rttvar: f64,
    rto: Duration,
    has_rtt_sample: bool,

    loss_window: [bool; 256],
    loss_window_index: usize,
    loss_window_count: usize,

    total_packets_sent: u64,
    total_packets_acked: u64,
    total_packets_lost: u64,
    packets_evicted: u64,
    bytes_sent: u64,
    bytes_acked: u64,
}

#[derive(Debug, Clone)]
struct SentPacketRecord {
    channel_id: u8,
    channel_sequence: u16,
    send_time: Instant,
    size: usize,
    nack_count: u8,
}

impl ReliableEndpoint {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            local_sequence: 0,
            remote_sequence: 0,
            ack_bits: 0,
            sent_packets: HashMap::new(),
            received_packets: SequenceBuffer::new(buffer_size),
            max_sequence_distance: crate::config::DEFAULT_MAX_SEQUENCE_DISTANCE,
            max_in_flight: crate::config::DEFAULT_MAX_IN_FLIGHT,
            srtt: 0.0,
            rttvar: 0.0,
            rto: Duration::from_millis(INITIAL_RTO_MILLIS),
            has_rtt_sample: false,
            loss_window: [false; LOSS_WINDOW_SIZE],
            loss_window_index: 0,
            loss_window_count: 0,
            total_packets_sent: 0,
            total_packets_acked: 0,
            total_packets_lost: 0,
            packets_evicted: 0,
            bytes_sent: 0,
            bytes_acked: 0,
        }
    }

    pub fn with_max_in_flight(mut self, max: usize) -> Self {
        self.max_in_flight = max;
        self
    }

    /// Gets the next sequence number for outgoing packets.
    pub fn next_sequence(&mut self) -> u16 {
        let seq = self.local_sequence;
        self.local_sequence = self.local_sequence.wrapping_add(1);
        seq
    }

    /// Records a packet as sent for reliability tracking.
    pub fn on_packet_sent(
        &mut self,
        sequence: u16,
        send_time: Instant,
        channel_id: u8,
        channel_sequence: u16,
        size: usize,
    ) {
        if self.sent_packets.len() >= self.max_in_flight {
            self.evict_worst_in_flight();
        }

        self.sent_packets.insert(
            sequence,
            SentPacketRecord {
                channel_id,
                channel_sequence,
                send_time,
                size,
                nack_count: 0,
            },
        );
        self.total_packets_sent += 1;
        self.bytes_sent += size as u64;
    }

    /// Evict the in-flight packet with the oldest send_time.
    fn evict_worst_in_flight(&mut self) {
        let worst_seq = self
            .sent_packets
            .iter()
            .min_by_key(|(_, record)| record.send_time)
            .map(|(&seq, _)| seq);

        if let Some(seq) = worst_seq {
            self.sent_packets.remove(&seq);
            // Eviction is buffer management, not network loss — don't record a loss sample
            self.total_packets_lost += 1;
            self.packets_evicted += 1;
        }
    }

    /// Processes an incoming packet and updates ack information.
    pub fn on_packet_received(&mut self, sequence: u16, _receive_time: Instant) {
        let distance = sequence_diff(sequence, self.remote_sequence).unsigned_abs();
        if distance > self.max_sequence_distance as u32 {
            return;
        }

        if !self.received_packets.exists(sequence) {
            self.received_packets.insert(sequence, true);

            if sequence_greater_than(sequence, self.remote_sequence) {
                let diff = sequence_diff(sequence, self.remote_sequence) as u64;
                if diff <= ACK_BITS_WINDOW as u64 {
                    self.ack_bits = (self.ack_bits << diff) | (1 << (diff - 1));
                } else {
                    self.ack_bits = 0;
                }
                self.remote_sequence = sequence;
            } else {
                let diff = sequence_diff(self.remote_sequence, sequence) as u64;
                if diff > 0 && diff <= ACK_BITS_WINDOW as u64 {
                    self.ack_bits |= 1 << (diff - 1);
                }
            }
        }
    }

    /// Processes acknowledgments from the remote endpoint.
    /// Returns (acked_pairs, fast_retransmit_candidates).
    /// Acked pairs are (channel_id, channel_sequence) for acknowledged packets.
    /// Fast retransmit candidates are (channel_id, channel_sequence) for packets
    /// that have been NACKed enough times to trigger fast retransmit.
    pub fn process_acks(&mut self, ack: u16, ack_bits: u64) -> AckResult {
        let mut acked = SmallVec::new();

        // Collect all acked sequence numbers
        let mut acked_seqs: SmallVec<[u16; 16]> = SmallVec::new();
        if self.sent_packets.contains_key(&ack) {
            acked_seqs.push(ack);
        }
        for i in 0..ACK_BITS_WINDOW {
            if (ack_bits & (1 << i)) != 0 {
                let seq = ack.wrapping_sub(i + 1);
                if self.sent_packets.contains_key(&seq) {
                    acked_seqs.push(seq);
                }
            }
        }

        // Process acks
        for &seq in &acked_seqs {
            if let Some(pair) = self.ack_single(seq) {
                acked.push(pair);
            }
        }

        // Increment nack_count for in-flight packets older than ack that are NOT in ack_bits
        let mut fast_retransmit = SmallVec::new();
        let in_flight_seqs: SmallVec<[u16; 32]> = self.sent_packets.keys().copied().collect();
        for seq in in_flight_seqs {
            // Only consider packets older than ack
            if !sequence_greater_than(ack, seq) {
                continue;
            }
            let diff = sequence_diff(ack, seq);
            if diff <= 0 || diff > ACK_BITS_WINDOW as i32 {
                continue;
            }
            // Check if this seq is covered by ack_bits
            let bit_index = diff as u64 - 1;
            if (ack_bits & (1 << bit_index)) != 0 {
                continue;
            }
            // Not acked — increment nack
            if let Some(record) = self.sent_packets.get_mut(&seq) {
                record.nack_count = record.nack_count.saturating_add(1);
                if record.nack_count == FAST_RETRANSMIT_THRESHOLD {
                    fast_retransmit.push((record.channel_id, record.channel_sequence));
                }
            }
        }

        (acked, fast_retransmit)
    }

    fn ack_single(&mut self, sequence: u16) -> Option<(u8, u16)> {
        if let Some(record) = self.sent_packets.remove(&sequence) {
            let rtt_sample = record.send_time.elapsed().as_secs_f64() * 1000.0;
            self.update_rtt(rtt_sample);

            self.total_packets_acked += 1;
            self.bytes_acked += record.size as u64;

            self.record_loss_sample(false);

            Some((record.channel_id, record.channel_sequence))
        } else {
            None
        }
    }

    /// Update RTT using Jacobson/Karels algorithm.
    pub fn update_rtt(&mut self, sample_ms: f64) {
        if !self.has_rtt_sample {
            self.srtt = sample_ms;
            self.rttvar = sample_ms / 2.0;
            self.has_rtt_sample = true;
        } else {
            self.rttvar = (1.0 - RTT_BETA) * self.rttvar + RTT_BETA * (sample_ms - self.srtt).abs();
            self.srtt = (1.0 - RTT_ALPHA) * self.srtt + RTT_ALPHA * sample_ms;
        }
        let rto_ms = (self.srtt + 4.0 * self.rttvar).clamp(MIN_RTO_MS, MAX_RTO_MS);
        self.rto = Duration::from_millis(rto_ms as u64);
    }

    pub fn record_loss_sample(&mut self, lost: bool) {
        self.loss_window[self.loss_window_index % LOSS_WINDOW_SIZE] = lost;
        self.loss_window_index += 1;
        if self.loss_window_count < LOSS_WINDOW_SIZE {
            self.loss_window_count += 1;
        }
    }

    /// Gets current ack information to include in outgoing packets.
    pub fn get_ack_info(&self) -> (u16, u64) {
        (self.remote_sequence, self.ack_bits)
    }

    /// Returns the current adaptive RTO.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Returns smoothed RTT in milliseconds.
    pub fn srtt_ms(&self) -> f64 {
        self.srtt
    }

    /// Calculates packet loss percentage from rolling window.
    pub fn packet_loss_percent(&self) -> f32 {
        if self.loss_window_count == 0 {
            return 0.0;
        }
        let lost = self.loss_window[..self.loss_window_count.min(LOSS_WINDOW_SIZE)]
            .iter()
            .filter(|&&l| l)
            .count();
        lost as f32 / self.loss_window_count as f32
    }

    /// Returns true if the given packet sequence is still in-flight (not yet acked).
    pub fn is_in_flight(&self, sequence: u16) -> bool {
        self.sent_packets.contains_key(&sequence)
    }

    pub fn packets_in_flight(&self) -> usize {
        self.sent_packets.len()
    }

    pub fn packets_evicted(&self) -> u64 {
        self.packets_evicted
    }

    pub fn stats(&self) -> ReliabilityStats {
        ReliabilityStats {
            packets_in_flight: self.sent_packets.len(),
            local_sequence: self.local_sequence,
            remote_sequence: self.remote_sequence,
            srtt_ms: self.srtt,
            rttvar_ms: self.rttvar,
            rto_ms: self.rto.as_millis() as f64,
            packet_loss: self.packet_loss_percent(),
            total_sent: self.total_packets_sent,
            total_acked: self.total_packets_acked,
            total_lost: self.total_packets_lost,
            packets_evicted: self.packets_evicted,
        }
    }
}

/// A circular buffer for tracking sequence numbers.
#[derive(Debug)]
pub struct SequenceBuffer<T> {
    entries: Vec<Option<(u16, T)>>,
    sequence: u16,
    size: usize,
}

impl<T> SequenceBuffer<T> {
    pub fn new(size: usize) -> Self {
        let mut entries = Vec::with_capacity(size);
        for _ in 0..size {
            entries.push(None);
        }
        Self {
            entries,
            sequence: 0,
            size,
        }
    }

    pub fn insert(&mut self, sequence: u16, data: T) {
        if sequence_greater_than(sequence, self.sequence) {
            let diff = sequence_diff(sequence, self.sequence) as usize;
            if diff < self.size {
                for _ in 0..diff {
                    self.sequence = self.sequence.wrapping_add(1);
                    let index = self.sequence as usize % self.size;
                    self.entries[index] = None;
                }
            } else {
                for entry in &mut self.entries {
                    *entry = None;
                }
                self.sequence = sequence;
            }
        }

        let index = sequence as usize % self.size;
        self.entries[index] = Some((sequence, data));
    }

    pub fn exists(&self, sequence: u16) -> bool {
        let index = sequence as usize % self.size;
        matches!(&self.entries[index], Some((stored_seq, _)) if *stored_seq == sequence)
    }

    pub fn get(&self, sequence: u16) -> Option<&T> {
        let index = sequence as usize % self.size;
        match &self.entries[index] {
            Some((stored_seq, data)) if *stored_seq == sequence => Some(data),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_convergence() {
        let mut endpoint = ReliableEndpoint::new(256);

        // Directly feed RTT samples to test the algorithm
        for _ in 0..20 {
            endpoint.update_rtt(50.0);
        }

        assert!(
            endpoint.srtt_ms() > 40.0 && endpoint.srtt_ms() < 60.0,
            "SRTT {} should be near 50ms",
            endpoint.srtt_ms()
        );
    }

    #[test]
    fn test_adaptive_rto() {
        let mut endpoint = ReliableEndpoint::new(256);

        // First sample
        endpoint.update_rtt(50.0);
        assert!(endpoint.rto.as_millis() >= 50);

        // High jitter sample
        endpoint.update_rtt(200.0);
        assert!(
            endpoint.rto.as_millis() > 50,
            "RTO should increase with jitter"
        );

        // RTO bounded
        endpoint.update_rtt(5000.0);
        assert!(
            endpoint.rto.as_millis() <= 2000,
            "RTO should be capped at 2s"
        );
    }

    #[test]
    fn test_packet_loss_tracking() {
        let mut endpoint = ReliableEndpoint::new(256);

        // Simulate mixed success/failure by directly recording samples
        for _ in 0..8 {
            endpoint.record_loss_sample(false); // success
        }
        for _ in 0..2 {
            endpoint.record_loss_sample(true); // loss
        }

        let loss = endpoint.packet_loss_percent();
        assert!(
            (loss - 0.2).abs() < 0.01,
            "Should be ~20% loss, got {}",
            loss
        );
    }

    #[test]
    fn test_sequence_buffer_operations() {
        let mut buffer: SequenceBuffer<u32> = SequenceBuffer::new(16);

        buffer.insert(0, 100);
        buffer.insert(1, 200);
        buffer.insert(2, 300);

        assert!(buffer.exists(0));
        assert!(buffer.exists(1));
        assert!(buffer.exists(2));
        assert!(!buffer.exists(3));

        assert_eq!(*buffer.get(0).unwrap(), 100);
        assert_eq!(*buffer.get(1).unwrap(), 200);
        assert_eq!(*buffer.get(2).unwrap(), 300);
    }

    #[test]
    fn test_sequence_buffer_wraparound() {
        let mut buffer: SequenceBuffer<u32> = SequenceBuffer::new(16);

        // Insert near u16::MAX
        buffer.insert(65534, 100);
        buffer.insert(65535, 200);
        buffer.insert(0, 300);
        buffer.insert(1, 400);

        assert!(buffer.exists(65534));
        assert!(buffer.exists(65535));
        assert!(buffer.exists(0));
        assert!(buffer.exists(1));
    }

    #[test]
    fn test_in_flight_cap_eviction() {
        let mut endpoint = ReliableEndpoint::new(256).with_max_in_flight(4);
        let now = Instant::now();

        // Send 4 packets (at capacity)
        for i in 0..4u16 {
            endpoint.on_packet_sent(i, now, 0, i, 100);
        }
        assert_eq!(endpoint.packets_in_flight(), 4);

        // Send a 5th — should evict one
        endpoint.on_packet_sent(4, now, 0, 4, 100);
        assert_eq!(endpoint.packets_in_flight(), 4);
        assert_eq!(endpoint.packets_evicted(), 1);
    }

    #[test]
    fn test_sequence_buffer_collision() {
        // Two sequences that map to the same index should not collide
        let mut buffer: SequenceBuffer<u32> = SequenceBuffer::new(16);

        buffer.insert(0, 100);
        assert!(buffer.exists(0));

        // Sequence 16 maps to the same slot as 0 (16 % 16 == 0)
        buffer.insert(16, 200);
        assert!(buffer.exists(16));
        // Old entry at sequence 0 should no longer exist
        assert!(!buffer.exists(0));
        assert_eq!(*buffer.get(16).unwrap(), 200);
        assert!(buffer.get(0).is_none());
    }

    #[test]
    fn test_ack_bits_no_false_ack() {
        let mut endpoint = ReliableEndpoint::new(256);

        // Receive packet 0, then packet 2 (skip 1)
        endpoint.on_packet_received(0, Instant::now());
        endpoint.on_packet_received(2, Instant::now());

        let (ack, ack_bits) = endpoint.get_ack_info();
        assert_eq!(ack, 2, "remote_sequence should be 2");
        // Bit 0 should be set (sequence 2-1=1 distance), but seq 1 was NOT received
        // Bit 1 should be set (sequence 2-2=0 distance) for seq 0
        // ack_bits bit i represents ack - (i+1), so:
        //   bit 0 = ack-1 = seq 1 (NOT received, should be 0)
        //   bit 1 = ack-2 = seq 0 (received, should be 1)
        assert_eq!(ack_bits & 1, 0, "seq 1 was not received, bit 0 should be 0");
        assert_ne!(ack_bits & 2, 0, "seq 0 was received, bit 1 should be set");
    }

    #[test]
    fn test_process_acks_returns_channel_info() {
        let mut endpoint = ReliableEndpoint::new(256);
        let now = Instant::now();

        endpoint.on_packet_sent(10, now, 2, 5, 100);
        endpoint.on_packet_sent(11, now, 3, 7, 200);

        // ACK packet 10 directly, packet 11 via ack_bits
        let (acked, _fast_retransmit) = endpoint.process_acks(11, 1); // bit 0 = seq 10
        assert_eq!(acked.len(), 2);
        // Should contain both (3, 7) for seq 11 and (2, 5) for seq 10
        assert!(acked.contains(&(3, 7)));
        assert!(acked.contains(&(2, 5)));
    }
}
