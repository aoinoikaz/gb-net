//! Connection state machine for reliable UDP: handshake, channels,
//! reliability tracking, congestion control, and fragmentation.
use rand::random;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use crate::{
    channel::{Channel, ChannelError},
    congestion::{BandwidthTracker, CongestionController, CongestionWindow},
    fragment::{FragmentAssembler, MtuDiscovery},
    packet::{Packet, PacketHeader},
    reliability::ReliableEndpoint,
    socket::SocketError,
    NetworkConfig, NetworkStats,
};

mod handshake;
mod io;

/// States of the connection state machine.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    ChallengeResponse,
    Connected,
    Disconnecting,
}

/// Errors that can occur during connection operations.
#[derive(Debug)]
pub enum ConnectionError {
    NotConnected,
    AlreadyConnected,
    ConnectionDenied(u8),
    Timeout,
    ProtocolMismatch,
    InvalidPacket,
    InvalidChannel(u8),
    SocketError(SocketError),
    ChannelError(ChannelError),
    MessageTooLarge,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::NotConnected => write!(f, "Not connected"),
            ConnectionError::AlreadyConnected => write!(f, "Already connected"),
            ConnectionError::ConnectionDenied(r) => write!(f, "Connection denied: {}", r),
            ConnectionError::Timeout => write!(f, "Connection timed out"),
            ConnectionError::ProtocolMismatch => write!(f, "Protocol mismatch"),
            ConnectionError::InvalidPacket => write!(f, "Invalid packet"),
            ConnectionError::InvalidChannel(ch) => write!(f, "Invalid channel: {}", ch),
            ConnectionError::SocketError(e) => write!(f, "Socket error: {}", e),
            ConnectionError::ChannelError(e) => write!(f, "Channel error: {}", e),
            ConnectionError::MessageTooLarge => write!(f, "Message too large"),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<SocketError> for ConnectionError {
    fn from(err: SocketError) -> Self {
        ConnectionError::SocketError(err)
    }
}

impl From<ChannelError> for ConnectionError {
    fn from(err: ChannelError) -> Self {
        ConnectionError::ChannelError(err)
    }
}

/// Typed disconnect reason decoded from the wire `u8` code.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DisconnectReason {
    Timeout,
    Requested,
    Kicked,
    ServerFull,
    ProtocolMismatch,
    Unknown(u8),
}

impl From<u8> for DisconnectReason {
    fn from(val: u8) -> Self {
        match val {
            0 => DisconnectReason::Timeout,
            1 => DisconnectReason::Requested,
            2 => DisconnectReason::Kicked,
            3 => DisconnectReason::ServerFull,
            4 => DisconnectReason::ProtocolMismatch,
            other => DisconnectReason::Unknown(other),
        }
    }
}

/// A single peer connection managing handshake, channels, reliability, and congestion.
pub struct Connection {
    pub(crate) config: NetworkConfig,
    pub(crate) state: ConnectionState,
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,

    pub(crate) client_salt: u64,
    pub(crate) server_salt: u64,

    pub(crate) last_packet_send_time: Instant,
    pub(crate) last_packet_recv_time: Instant,
    pub(crate) connection_start_time: Option<Instant>,
    pub(crate) connection_request_time: Option<Instant>,
    pub(crate) connection_retry_count: u32,

    pub(crate) local_sequence: u16,
    pub(crate) remote_sequence: u16,
    pub(crate) ack_bits: u64,
    pub(crate) reliability: ReliableEndpoint,

    pub(crate) channels: Vec<Channel>,

    pub(crate) send_queue: VecDeque<Packet>,
    pub(crate) recv_queue: VecDeque<Packet>,

    pub(crate) congestion: CongestionController,
    pub(crate) cwnd: Option<CongestionWindow>,
    pub(crate) bandwidth_up: BandwidthTracker,
    pub(crate) bandwidth_down: BandwidthTracker,
    pub(crate) fragment_assembler: FragmentAssembler,
    pub(crate) mtu_discovery: MtuDiscovery,

    #[cfg(feature = "encryption")]
    pub(crate) encryption_state: Option<crate::security::EncryptionState>,

    pub(crate) channel_priority_order: Vec<usize>,

    pub(crate) stats: NetworkStats,

    pub(crate) disconnect_retry_count: u32,
    pub(crate) disconnect_time: Option<Instant>,

    pub(crate) pending_ack_send: bool,
    pub(crate) data_sent_this_tick: bool,
    pub(crate) next_fragment_id: u32,
    /// Tracks per-fragment packet sequences for selective retransmission.
    /// Maps fragment_message_id → Vec<(packet_seq, fragment_index, fragment_data)>
    pub(crate) pending_fragments: HashMap<u32, Vec<(u16, u8, Vec<u8>)>>,
}

impl Connection {
    pub fn new(config: NetworkConfig, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let mut channels = Vec::with_capacity(config.max_channels);
        if config.channel_configs.is_empty() {
            let channel_config = config.default_channel_config;
            for i in 0..config.max_channels {
                channels.push(Channel::new(i as u8, channel_config));
            }
        } else {
            for (i, cfg) in config.channel_configs.iter().enumerate() {
                channels.push(Channel::new(i as u8, *cfg));
            }
            for i in config.channel_configs.len()..config.max_channels {
                channels.push(Channel::new(i as u8, config.default_channel_config));
            }
        }

        let mut channel_priority_order: Vec<usize> = (0..channels.len()).collect();
        channel_priority_order.sort_by_key(|&i| channels[i].config_priority());

        let packet_buffer_size = config.packet_buffer_size;
        let max_in_flight = config.max_in_flight;
        let congestion = CongestionController::new(
            config.send_rate,
            config.congestion_bad_loss_threshold,
            config.congestion_good_rtt_threshold,
            config.congestion_recovery_time,
        );
        let cwnd = if config.use_cwnd_congestion {
            Some(CongestionWindow::new(config.mtu))
        } else {
            None
        };
        let bandwidth_up = BandwidthTracker::new(std::time::Duration::from_secs(1));
        let bandwidth_down = BandwidthTracker::new(std::time::Duration::from_secs(1));
        let fragment_assembler =
            FragmentAssembler::new(config.fragment_timeout, config.max_reassembly_buffer_size);
        let mtu_discovery = MtuDiscovery::new(crate::fragment::MIN_MTU, config.mtu);

        #[cfg(feature = "encryption")]
        let encryption_state = config
            .encryption_key
            .and_then(|key| crate::security::EncryptionState::new(&key).ok());

        Self {
            config,
            state: ConnectionState::Disconnected,
            local_addr,
            remote_addr,
            client_salt: random(),
            server_salt: 0,
            last_packet_send_time: Instant::now(),
            last_packet_recv_time: Instant::now(),
            connection_start_time: None,
            connection_request_time: None,
            connection_retry_count: 0,
            local_sequence: 0,
            remote_sequence: 0,
            ack_bits: 0,
            reliability: ReliableEndpoint::new(packet_buffer_size)
                .with_max_in_flight(max_in_flight),
            channels,
            channel_priority_order,
            congestion,
            cwnd,
            bandwidth_up,
            bandwidth_down,
            fragment_assembler,
            mtu_discovery,
            send_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
            #[cfg(feature = "encryption")]
            encryption_state,
            stats: NetworkStats::default(),
            disconnect_retry_count: 0,
            disconnect_time: None,
            pending_ack_send: false,
            data_sent_this_tick: false,
            next_fragment_id: 0,
            pending_fragments: HashMap::new(),
        }
    }

    pub fn send(
        &mut self,
        channel_id: u8,
        data: &[u8],
        reliable: bool,
    ) -> Result<(), ConnectionError> {
        if self.state != ConnectionState::Connected {
            return Err(ConnectionError::NotConnected);
        }

        if channel_id as usize >= self.channels.len() {
            return Err(ConnectionError::InvalidChannel(channel_id));
        }

        self.channels[channel_id as usize].send(data, reliable)?;
        Ok(())
    }

    pub fn receive(&mut self, channel_id: u8) -> Option<Vec<u8>> {
        if channel_id as usize >= self.channels.len() {
            return None;
        }
        self.channels[channel_id as usize].receive()
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    pub(crate) fn create_header(&mut self) -> PacketHeader {
        let (ack, ack_bits) = self.reliability.get_ack_info();
        let seq = self.local_sequence;
        self.local_sequence = self.local_sequence.wrapping_add(1);
        PacketHeader {
            protocol_id: self.config.protocol_id,
            sequence: seq,
            ack,
            ack_bits,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    pub fn stats(&self) -> &NetworkStats {
        &self.stats
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Token for connection migration validation: XOR of client and server salts.
    pub fn migration_token(&self) -> u64 {
        self.client_salt ^ self.server_salt
    }

    /// Update the remote address (used during connection migration).
    pub fn set_remote_addr(&mut self, addr: SocketAddr) {
        self.remote_addr = addr;
    }

    pub fn client_salt(&self) -> u64 {
        self.client_salt
    }

    pub fn server_salt(&self) -> u64 {
        self.server_salt
    }

    pub fn set_server_salt(&mut self, salt: u64) {
        self.server_salt = salt;
    }

    pub fn touch_recv_time(&mut self) {
        self.last_packet_recv_time = Instant::now();
    }

    pub fn last_recv_elapsed(&self) -> std::time::Duration {
        self.last_packet_recv_time.elapsed()
    }

    pub fn last_send_elapsed(&self) -> std::time::Duration {
        self.last_packet_send_time.elapsed()
    }

    pub fn touch_send_time(&mut self) {
        self.last_packet_send_time = Instant::now();
    }

    /// Get next outgoing message from a channel (used by client/server).
    pub fn get_channel_outgoing(&mut self, channel: u8) -> Option<(u16, Vec<u8>)> {
        if (channel as usize) < self.channels.len() {
            self.channels[channel as usize].get_outgoing_message()
        } else {
            None
        }
    }

    /// Directly deliver a payload to a channel (used by server).
    pub fn receive_payload_direct(&mut self, channel: u8, payload: Vec<u8>) {
        if (channel as usize) < self.channels.len() {
            self.channels[channel as usize].on_packet_received(payload);
        }
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    pub fn channel_stats(&self) -> Vec<crate::stats::ChannelStats> {
        self.channels.iter().map(|ch| ch.stats()).collect()
    }

    pub fn reliability_stats(&self) -> crate::stats::ReliabilityStats {
        self.reliability.stats()
    }

    /// Process an incoming packet's header for reliability tracking (ACKs, sequence).
    /// Called by server/client after deserializing a data packet from a connected peer.
    pub fn process_incoming_header(&mut self, header: &crate::packet::PacketHeader) {
        use std::time::Instant;

        self.reliability
            .on_packet_received(header.sequence, Instant::now());
        self.pending_ack_send = true;

        if crate::util::sequence_greater_than(header.sequence, self.remote_sequence) {
            self.remote_sequence = header.sequence;
        }

        let (acked_pairs, fast_retransmit) =
            self.reliability.process_acks(header.ack, header.ack_bits);
        // Feed ack info to cwnd if enabled
        if let Some(ref mut cw) = self.cwnd {
            let acked_bytes = acked_pairs.len() * self.config.mtu;
            if acked_bytes > 0 {
                cw.on_ack(acked_bytes);
            }
        }

        for (channel_id, channel_seq) in acked_pairs {
            if (channel_id as usize) < self.channels.len() {
                self.channels[channel_id as usize].acknowledge_message(channel_seq);
            }
        }
        for (channel_id, channel_seq) in fast_retransmit {
            if (channel_id as usize) < self.channels.len() {
                self.channels[channel_id as usize].mark_for_fast_retransmit(channel_seq);
            }
        }

        // Clean up fully-acked fragment groups
        self.pending_fragments.retain(|_, entries| {
            entries.retain(|(pkt_seq, _, _)| self.reliability.is_in_flight(*pkt_seq));
            !entries.is_empty()
        });
    }

    /// Drain the send queue, returning packets that need to be sent over the wire.
    pub fn drain_send_queue(&mut self) -> Vec<Packet> {
        self.send_queue.drain(..).collect()
    }

    /// Record that bytes were sent (for bandwidth tracking).
    pub fn record_bytes_sent(&mut self, bytes: usize) {
        self.bandwidth_up.record(bytes);
        self.last_packet_send_time = Instant::now();
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += bytes as u64;
    }

    /// Record that bytes were received (for bandwidth tracking).
    pub fn record_bytes_received(&mut self, bytes: usize) {
        self.bandwidth_down.record(bytes);
        self.stats.packets_received += 1;
        self.stats.bytes_received += bytes as u64;
    }
}
