//! Network configuration constants and structures.
//!
//! [`NetworkConfig`] controls all tunable parameters: timeouts, MTU, channels,
//! congestion, and encryption. [`ChannelConfig`] configures individual channel
//! delivery modes.
use std::time::Duration;

pub const DEFAULT_PROTOCOL_ID: u32 = 0x12345678;
pub const DEFAULT_MAX_CLIENTS: usize = 64;
pub const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 1;
pub const DEFAULT_CONNECTION_REQUEST_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_CONNECTION_REQUEST_MAX_RETRIES: u32 = 5;
pub const DEFAULT_MTU: usize = 1200;
pub const DEFAULT_FRAGMENT_THRESHOLD: usize = 1024;
pub const DEFAULT_FRAGMENT_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_MAX_FRAGMENTS: usize = 256;
pub const DEFAULT_MAX_REASSEMBLY_BUFFER_SIZE: usize = 1024 * 1024;
pub const DEFAULT_PACKET_BUFFER_SIZE: usize = 256;
pub const DEFAULT_ACK_BUFFER_SIZE: usize = 256;
pub const DEFAULT_MAX_SEQUENCE_DISTANCE: u16 = 32768;
pub const DEFAULT_RELIABLE_RETRY_TIME_MILLIS: u64 = 100;
pub const DEFAULT_MAX_RELIABLE_RETRIES: u32 = 10;
pub const DEFAULT_MAX_CHANNELS: usize = 8;
pub const DEFAULT_SEND_RATE_HZ: f32 = 60.0;
pub const DEFAULT_MAX_PACKET_RATE_HZ: f32 = 120.0;
pub const DEFAULT_CONGESTION_THRESHOLD: f32 = 0.1;
pub const DEFAULT_CONGESTION_GOOD_RTT_THRESHOLD_MS: f32 = 250.0;
pub const DEFAULT_CONGESTION_BAD_LOSS_THRESHOLD: f32 = 0.1;
pub const DEFAULT_CONGESTION_RECOVERY_TIME_SECS: u64 = 10;
pub const DEFAULT_DISCONNECT_RETRIES: u32 = 3;
pub const DEFAULT_DISCONNECT_RETRY_TIMEOUT_MILLIS: u64 = 500;
pub const DEFAULT_MAX_BANDWIDTH_UNLIMITED: usize = 0;
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
pub const DEFAULT_MESSAGE_BUFFER_SIZE: usize = 1024;
pub const DEFAULT_MAX_PENDING: usize = 256;
pub const DEFAULT_ORDERED_BUFFER_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_MAX_ORDERED_BUFFER_SIZE: usize = 1024;
pub const DEFAULT_RATE_LIMIT_PER_SECOND: usize = 10;
pub const DEFAULT_COOKIE_WINDOW_SECS: u64 = 5;
pub const DEFAULT_DELTA_BASELINE_TIMEOUT_SECS: u64 = 2;
pub const DEFAULT_MAX_BASELINE_SNAPSHOTS: usize = 32;
pub const DEFAULT_MAX_IN_FLIGHT: usize = 256;
pub const DEFAULT_MAX_TRACKED_TOKENS: usize = 4096;
pub const DEFAULT_CHANNEL_PRIORITY: u8 = 128;

/// Maximum exponential backoff exponent for retransmission (caps at 2^5 = 32x RTO).
pub const MAX_BACKOFF_EXPONENT: u32 = 5;

pub const MIN_MTU: usize = 576;
pub const MAX_MTU: usize = 65535;
pub const MAX_CHANNEL_COUNT: usize = 256;

/// The 5 LiteNetLib-style delivery modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryMode {
    /// Fire and forget, no sequence tracking.
    Unreliable,
    /// Deliver only if newer than last received, drop stale.
    UnreliableSequenced,
    /// ACK-based retransmission, deliver immediately on arrival.
    ReliableUnordered,
    /// ACK + buffer out-of-order, deliver in sequence.
    ReliableOrdered,
    /// ACK + deliver only latest, drop stale but still retransmit for ACK purposes.
    ReliableSequenced,
}

impl DeliveryMode {
    /// Returns `true` if this mode provides guaranteed delivery.
    pub fn is_reliable(&self) -> bool {
        matches!(
            self,
            DeliveryMode::ReliableUnordered
                | DeliveryMode::ReliableOrdered
                | DeliveryMode::ReliableSequenced
        )
    }

    /// Returns `true` if this mode drops stale (out-of-sequence) messages.
    pub fn is_sequenced(&self) -> bool {
        matches!(
            self,
            DeliveryMode::UnreliableSequenced | DeliveryMode::ReliableSequenced
        )
    }

    /// Returns `true` if this mode buffers and delivers messages in send order.
    pub fn is_ordered(&self) -> bool {
        matches!(self, DeliveryMode::ReliableOrdered)
    }
}

/// Configuration validation error.
#[derive(Debug, Clone)]
pub enum ConfigError {
    FragmentThresholdExceedsMtu,
    InvalidChannelCount,
    InvalidPacketBufferSize,
    InvalidMtu,
    TimeoutNotGreaterThanKeepalive,
    InvalidMaxClients,
    ChannelConfigsExceedMaxChannels,
    InvalidSendRate,
    InvalidMaxPacketRate,
    InvalidMaxInFlight,
    InvalidFragmentThreshold,
    SendRateExceedsMaxPacketRate,
    InvalidCongestionThreshold,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::FragmentThresholdExceedsMtu => {
                write!(f, "fragment_threshold must be <= mtu")
            }
            ConfigError::InvalidChannelCount => {
                write!(f, "max_channels must be > 0 and <= {MAX_CHANNEL_COUNT}")
            }
            ConfigError::InvalidPacketBufferSize => {
                write!(f, "packet_buffer_size must be > 0")
            }
            ConfigError::InvalidMtu => {
                write!(f, "mtu must be >= {MIN_MTU} and <= {MAX_MTU}")
            }
            ConfigError::TimeoutNotGreaterThanKeepalive => {
                write!(f, "connection_timeout must be > keepalive_interval")
            }
            ConfigError::InvalidMaxClients => {
                write!(f, "max_clients must be > 0")
            }
            ConfigError::ChannelConfigsExceedMaxChannels => {
                write!(f, "channel_configs.len() must be <= max_channels")
            }
            ConfigError::InvalidSendRate => {
                write!(f, "send_rate must be > 0.0 and not NaN")
            }
            ConfigError::InvalidMaxPacketRate => {
                write!(f, "max_packet_rate must be > 0.0 and not NaN")
            }
            ConfigError::InvalidMaxInFlight => {
                write!(f, "max_in_flight must be > 0")
            }
            ConfigError::InvalidFragmentThreshold => {
                write!(f, "fragment_threshold must be > 0")
            }
            ConfigError::SendRateExceedsMaxPacketRate => {
                write!(f, "send_rate must be <= max_packet_rate")
            }
            ConfigError::InvalidCongestionThreshold => {
                write!(f, "congestion thresholds must be finite and not NaN")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Top-level network configuration for both client and server.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub protocol_id: u32,
    pub max_clients: usize,

    pub connection_timeout: Duration,
    pub keepalive_interval: Duration,
    pub connection_request_timeout: Duration,
    pub connection_request_max_retries: u32,

    pub mtu: usize,
    pub fragment_threshold: usize,
    pub fragment_timeout: Duration,
    pub max_fragments: usize,
    pub max_reassembly_buffer_size: usize,

    pub packet_buffer_size: usize,
    pub ack_buffer_size: usize,
    pub max_sequence_distance: u16,
    pub reliable_retry_time: Duration,
    pub max_reliable_retries: u32,
    pub max_in_flight: usize,

    pub max_channels: usize,
    pub default_channel_config: ChannelConfig,
    pub channel_configs: Vec<ChannelConfig>,

    pub send_rate: f32,
    pub max_packet_rate: f32,
    pub congestion_threshold: f32,

    pub encryption: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub max_tracked_tokens: usize,

    pub congestion_good_rtt_threshold: f32,
    pub congestion_bad_loss_threshold: f32,
    pub congestion_recovery_time: Duration,

    pub simulation: Option<SimulationConfig>,

    pub disconnect_retries: u32,
    pub disconnect_retry_timeout: Duration,

    pub max_bandwidth_bytes_per_sec: usize,
    pub max_pending: usize,
    pub rate_limit_per_second: usize,

    pub enable_stateless_cookie: bool,
    pub use_cwnd_congestion: bool,

    pub delta_baseline_timeout: Duration,
    pub max_baseline_snapshots: usize,

    pub enable_connection_migration: bool,
}

fn is_valid_positive_f32(v: f32) -> bool {
    v > 0.0 && !v.is_nan()
}

fn is_finite_f32(v: f32) -> bool {
    v.is_finite()
}

impl NetworkConfig {
    /// Validates the configuration, returning an error if any values are invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.fragment_threshold > self.mtu {
            return Err(ConfigError::FragmentThresholdExceedsMtu);
        }
        if self.max_channels == 0 || self.max_channels > MAX_CHANNEL_COUNT {
            return Err(ConfigError::InvalidChannelCount);
        }
        if self.packet_buffer_size == 0 {
            return Err(ConfigError::InvalidPacketBufferSize);
        }
        if self.mtu < MIN_MTU || self.mtu > MAX_MTU {
            return Err(ConfigError::InvalidMtu);
        }
        if self.connection_timeout <= self.keepalive_interval {
            return Err(ConfigError::TimeoutNotGreaterThanKeepalive);
        }
        if self.max_clients == 0 {
            return Err(ConfigError::InvalidMaxClients);
        }
        if self.channel_configs.len() > self.max_channels {
            return Err(ConfigError::ChannelConfigsExceedMaxChannels);
        }
        if !is_valid_positive_f32(self.send_rate) {
            return Err(ConfigError::InvalidSendRate);
        }
        if !is_valid_positive_f32(self.max_packet_rate) {
            return Err(ConfigError::InvalidMaxPacketRate);
        }
        if self.max_in_flight == 0 {
            return Err(ConfigError::InvalidMaxInFlight);
        }
        if self.fragment_threshold == 0 {
            return Err(ConfigError::InvalidFragmentThreshold);
        }
        if self.send_rate > self.max_packet_rate {
            return Err(ConfigError::SendRateExceedsMaxPacketRate);
        }
        if !is_finite_f32(self.congestion_good_rtt_threshold)
            || !is_finite_f32(self.congestion_bad_loss_threshold)
            || !is_finite_f32(self.congestion_threshold)
        {
            return Err(ConfigError::InvalidCongestionThreshold);
        }
        Ok(())
    }
}

impl NetworkConfig {
    pub fn with_protocol_id(mut self, id: u32) -> Self {
        self.protocol_id = id;
        self
    }
    pub fn with_max_clients(mut self, max: usize) -> Self {
        self.max_clients = max;
        self
    }
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }
    pub fn with_keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = interval;
        self
    }
    pub fn with_max_channels(mut self, channels: usize) -> Self {
        self.max_channels = channels;
        self
    }
    pub fn with_send_rate(mut self, rate: f32) -> Self {
        self.send_rate = rate;
        self
    }
    pub fn with_encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption = true;
        self.encryption_key = Some(key);
        self
    }
    pub fn with_channel_config(mut self, index: usize, config: ChannelConfig) -> Self {
        if index >= self.channel_configs.len() {
            self.channel_configs
                .resize(index + 1, ChannelConfig::default());
        }
        self.channel_configs[index] = config;
        self
    }
    pub fn with_rate_limit(mut self, per_second: usize) -> Self {
        self.rate_limit_per_second = per_second;
        self
    }
    pub fn with_max_in_flight(mut self, max: usize) -> Self {
        self.max_in_flight = max;
        self
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            protocol_id: DEFAULT_PROTOCOL_ID,
            max_clients: DEFAULT_MAX_CLIENTS,

            connection_timeout: Duration::from_secs(DEFAULT_CONNECTION_TIMEOUT_SECS),
            keepalive_interval: Duration::from_secs(DEFAULT_KEEPALIVE_INTERVAL_SECS),
            connection_request_timeout: Duration::from_secs(
                DEFAULT_CONNECTION_REQUEST_TIMEOUT_SECS,
            ),
            connection_request_max_retries: DEFAULT_CONNECTION_REQUEST_MAX_RETRIES,

            mtu: DEFAULT_MTU,
            fragment_threshold: DEFAULT_FRAGMENT_THRESHOLD,
            fragment_timeout: Duration::from_secs(DEFAULT_FRAGMENT_TIMEOUT_SECS),
            max_fragments: DEFAULT_MAX_FRAGMENTS,
            max_reassembly_buffer_size: DEFAULT_MAX_REASSEMBLY_BUFFER_SIZE,

            packet_buffer_size: DEFAULT_PACKET_BUFFER_SIZE,
            ack_buffer_size: DEFAULT_ACK_BUFFER_SIZE,
            max_sequence_distance: DEFAULT_MAX_SEQUENCE_DISTANCE,
            reliable_retry_time: Duration::from_millis(DEFAULT_RELIABLE_RETRY_TIME_MILLIS),
            max_reliable_retries: DEFAULT_MAX_RELIABLE_RETRIES,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,

            max_channels: DEFAULT_MAX_CHANNELS,
            default_channel_config: ChannelConfig::default(),
            channel_configs: Vec::new(),

            send_rate: DEFAULT_SEND_RATE_HZ,
            max_packet_rate: DEFAULT_MAX_PACKET_RATE_HZ,
            congestion_threshold: DEFAULT_CONGESTION_THRESHOLD,

            encryption: false,
            encryption_key: None,
            max_tracked_tokens: DEFAULT_MAX_TRACKED_TOKENS,

            congestion_good_rtt_threshold: DEFAULT_CONGESTION_GOOD_RTT_THRESHOLD_MS,
            congestion_bad_loss_threshold: DEFAULT_CONGESTION_BAD_LOSS_THRESHOLD,
            congestion_recovery_time: Duration::from_secs(DEFAULT_CONGESTION_RECOVERY_TIME_SECS),

            simulation: None,

            disconnect_retries: DEFAULT_DISCONNECT_RETRIES,
            disconnect_retry_timeout: Duration::from_millis(
                DEFAULT_DISCONNECT_RETRY_TIMEOUT_MILLIS,
            ),

            max_bandwidth_bytes_per_sec: DEFAULT_MAX_BANDWIDTH_UNLIMITED,

            max_pending: DEFAULT_MAX_PENDING,

            rate_limit_per_second: DEFAULT_RATE_LIMIT_PER_SECOND,

            enable_stateless_cookie: true,
            use_cwnd_congestion: false,

            delta_baseline_timeout: Duration::from_secs(DEFAULT_DELTA_BASELINE_TIMEOUT_SECS),
            max_baseline_snapshots: DEFAULT_MAX_BASELINE_SNAPSHOTS,

            enable_connection_migration: false,
        }
    }
}

/// Configuration for an individual message channel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChannelConfig {
    pub delivery_mode: DeliveryMode,
    pub max_message_size: usize,
    pub message_buffer_size: usize,
    pub block_on_full: bool,
    pub ordered_buffer_timeout: Duration,
    pub max_ordered_buffer_size: usize,
    pub max_reliable_retries: u32,
    pub priority: u8,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            delivery_mode: DeliveryMode::ReliableOrdered,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            message_buffer_size: DEFAULT_MESSAGE_BUFFER_SIZE,
            block_on_full: false,
            ordered_buffer_timeout: Duration::from_secs(DEFAULT_ORDERED_BUFFER_TIMEOUT_SECS),
            max_ordered_buffer_size: DEFAULT_MAX_ORDERED_BUFFER_SIZE,
            max_reliable_retries: DEFAULT_MAX_RELIABLE_RETRIES,
            priority: DEFAULT_CHANNEL_PRIORITY,
        }
    }
}

impl ChannelConfig {
    /// Preset: fire-and-forget, no guarantees.
    pub fn unreliable() -> Self {
        Self {
            delivery_mode: DeliveryMode::Unreliable,
            ..Default::default()
        }
    }

    /// Preset: unreliable with stale-packet dropping.
    pub fn unreliable_sequenced() -> Self {
        Self {
            delivery_mode: DeliveryMode::UnreliableSequenced,
            ..Default::default()
        }
    }

    /// Preset: guaranteed delivery, no ordering.
    pub fn reliable_unordered() -> Self {
        Self {
            delivery_mode: DeliveryMode::ReliableUnordered,
            ..Default::default()
        }
    }

    /// Preset: guaranteed delivery in send order.
    pub fn reliable_ordered() -> Self {
        Self {
            delivery_mode: DeliveryMode::ReliableOrdered,
            ..Default::default()
        }
    }

    /// Preset: guaranteed delivery, only latest message delivered.
    pub fn reliable_sequenced() -> Self {
        Self {
            delivery_mode: DeliveryMode::ReliableSequenced,
            ..Default::default()
        }
    }

    /// Sets the channel priority (lower value = higher priority).
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }
}

/// Configuration for network condition simulation.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    pub packet_loss: f32,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub duplicate_chance: f32,
    pub out_of_order_chance: f32,
    pub bandwidth_limit_bytes_per_sec: usize,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            packet_loss: 0.0,
            latency_ms: 0,
            jitter_ms: 0,
            duplicate_chance: 0.0,
            out_of_order_chance: 0.0,
            bandwidth_limit_bytes_per_sec: 0,
        }
    }
}
