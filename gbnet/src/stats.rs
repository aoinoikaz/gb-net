//! Consolidated statistics types for connections, channels, reliability, and sockets.
use std::time::Instant;

/// Connection quality indicator.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum ConnectionQuality {
    #[default]
    Good,
    Fair,
    Poor,
}

/// RTT threshold (ms) below which quality is considered Good.
pub const GOOD_RTT_THRESHOLD_MS: f32 = 100.0;
/// Packet loss threshold (ratio, 0.0–1.0) below which quality is considered Good.
pub const GOOD_LOSS_THRESHOLD: f32 = 0.02;
/// RTT threshold (ms) below which quality is considered Fair (above Good).
pub const FAIR_RTT_THRESHOLD_MS: f32 = 250.0;
/// Packet loss threshold (ratio, 0.0–1.0) below which quality is considered Fair (above Good).
pub const FAIR_LOSS_THRESHOLD: f32 = 0.1;

/// Assesses connection quality based on RTT and packet loss thresholds.
pub fn assess_connection_quality(rtt_ms: f32, loss_percent: f32) -> ConnectionQuality {
    if rtt_ms < GOOD_RTT_THRESHOLD_MS && loss_percent < GOOD_LOSS_THRESHOLD {
        ConnectionQuality::Good
    } else if rtt_ms < FAIR_RTT_THRESHOLD_MS && loss_percent < FAIR_LOSS_THRESHOLD {
        ConnectionQuality::Fair
    } else {
        ConnectionQuality::Poor
    }
}

/// Aggregate network statistics for a single connection.
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_loss: f32,
    pub rtt: f32,
    pub bandwidth_up: f32,
    pub bandwidth_down: f32,
    pub send_errors: u64,
    pub connection_quality: ConnectionQuality,
}

impl Default for NetworkStats {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packet_loss: 0.0,
            rtt: 0.0,
            bandwidth_up: 0.0,
            bandwidth_down: 0.0,
            send_errors: 0,
            connection_quality: ConnectionQuality::Good,
        }
    }
}

/// Per-channel message and buffer statistics.
#[derive(Debug, Clone)]
pub struct ChannelStats {
    pub id: u8,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub send_buffer_size: usize,
    pub pending_ack_count: usize,
    pub receive_buffer_size: usize,
    pub gap_sequences_skipped: u64,
    pub messages_dropped: u64,
}

/// Reliability subsystem statistics: in-flight packets, RTT, loss, and evictions.
#[derive(Debug, Clone)]
pub struct ReliabilityStats {
    pub packets_in_flight: usize,
    pub local_sequence: u16,
    pub remote_sequence: u16,
    pub srtt_ms: f64,
    pub rttvar_ms: f64,
    pub rto_ms: f64,
    pub packet_loss: f32,
    pub total_sent: u64,
    pub total_acked: u64,
    pub total_lost: u64,
    pub packets_evicted: u64,
}

/// Low-level socket I/O counters.
#[derive(Debug, Default)]
pub struct SocketStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_receive_time: Option<Instant>,
    pub last_send_time: Option<Instant>,
}
