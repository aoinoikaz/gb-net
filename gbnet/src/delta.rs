//! Delta compression transport: baseline tracking, encoding, and decoding.
//!
//! [`DeltaTracker`] manages per-sequence snapshots for delta encoding against
//! acknowledged baselines. [`BaselineManager`] provides a ring buffer of
//! confirmed snapshots per connection.

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use crate::serialize::bit_io::{BitBuffer, BitRead, BitWrite};
use crate::serialize::{BitDeserialize, BitSerialize, NetworkDelta};

/// Sequence number used to identify baseline snapshots on the wire.
pub type BaselineSeq = u16;

/// Sentinel value indicating no baseline is available (full state required).
pub const NO_BASELINE: BaselineSeq = u16::MAX;

/// Wire header size: 2 bytes for baseline_seq.
const BASELINE_SEQ_BITS: usize = 16;

/// Tracks snapshots and encodes deltas against acknowledged baselines.
pub struct DeltaTracker<T: NetworkDelta> {
    /// Unconfirmed snapshots awaiting ACK, ordered by sequence.
    pending: VecDeque<(BaselineSeq, T)>,
    /// The most recently ACK-confirmed baseline.
    confirmed_baseline: Option<(BaselineSeq, T)>,
    /// Maximum pending snapshots before oldest are dropped.
    max_pending: usize,
}

impl<T: NetworkDelta + BitSerialize + BitDeserialize + Clone> DeltaTracker<T> {
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: VecDeque::with_capacity(max_pending),
            confirmed_baseline: None,
            max_pending,
        }
    }

    /// Push a new snapshot for the given sequence. Returns encoded bytes
    /// containing `[baseline_seq: u16][delta_payload]`.
    pub fn encode(&mut self, seq: BaselineSeq, current: &T) -> io::Result<Vec<u8>> {
        let mut buf = BitBuffer::new();

        if let Some((base_seq, ref baseline)) = self.confirmed_baseline {
            let delta = current.diff(baseline);
            buf.write_bits(base_seq as u64, BASELINE_SEQ_BITS)?;
            delta.bit_serialize(&mut buf)?;
        } else {
            // No baseline — write sentinel + full state
            buf.write_bits(NO_BASELINE as u64, BASELINE_SEQ_BITS)?;
            current.bit_serialize(&mut buf)?;
        }

        // Store pending snapshot
        if self.pending.len() >= self.max_pending {
            self.pending.pop_front();
        }
        self.pending.push_back((seq, current.clone()));

        buf.into_bytes(true)
    }

    /// Called when a sequence is ACK'd. Promotes the matching snapshot to
    /// confirmed baseline and discards older pending entries.
    pub fn on_ack(&mut self, seq: BaselineSeq) {
        if let Some(pos) = self.pending.iter().position(|(s, _)| *s == seq) {
            let (ack_seq, snapshot) = self.pending.remove(pos).unwrap();
            self.confirmed_baseline = Some((ack_seq, snapshot));
            // Drop everything older than the acked position
            while self
                .pending
                .front()
                .is_some_and(|(s, _)| crate::util::sequence_diff(*s, ack_seq) < 0)
            {
                self.pending.pop_front();
            }
        }
    }

    /// Decode a delta-encoded payload. Requires access to the baseline manager
    /// to look up the referenced baseline.
    pub fn decode(data: &[u8], baselines: &BaselineManager<T>) -> io::Result<T> {
        let mut buf = BitBuffer::from_bytes(data.to_vec());
        let base_seq = buf.read_bits(BASELINE_SEQ_BITS)? as BaselineSeq;

        if base_seq == NO_BASELINE {
            T::bit_deserialize(&mut buf)
        } else {
            let baseline = baselines.get_baseline(base_seq).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Missing baseline for seq {}", base_seq),
                )
            })?;
            let delta = <T as NetworkDelta>::Delta::bit_deserialize(&mut buf)?;
            let mut state = baseline.clone();
            state.apply(&delta);
            Ok(state)
        }
    }

    /// Reset tracker state (e.g. on reconnect).
    pub fn reset(&mut self) {
        self.pending.clear();
        self.confirmed_baseline = None;
    }

    /// Returns the confirmed baseline sequence, if any.
    pub fn confirmed_seq(&self) -> Option<BaselineSeq> {
        self.confirmed_baseline.as_ref().map(|(s, _)| *s)
    }

    /// Create a tracker with config-driven capacity.
    pub fn from_config(config: &crate::NetworkConfig) -> Self {
        Self::new(config.max_baseline_snapshots)
    }
}

/// Ring buffer of confirmed snapshots per connection, used by the receiving
/// side to look up baselines referenced in incoming delta payloads.
pub struct BaselineManager<T> {
    snapshots: VecDeque<(BaselineSeq, T, Instant)>,
    max_snapshots: usize,
    timeout: Duration,
}

impl<T: Clone> BaselineManager<T> {
    pub fn new(max_snapshots: usize, timeout: Duration) -> Self {
        Self {
            snapshots: VecDeque::with_capacity(max_snapshots),
            max_snapshots,
            timeout,
        }
    }

    /// Store a confirmed snapshot at the given sequence.
    pub fn push_snapshot(&mut self, seq: BaselineSeq, state: T) {
        let now = Instant::now();
        // Evict expired
        while self
            .snapshots
            .front()
            .is_some_and(|(_, _, ts)| now.duration_since(*ts) > self.timeout)
        {
            self.snapshots.pop_front();
        }
        // Evict oldest if at capacity
        if self.snapshots.len() >= self.max_snapshots {
            self.snapshots.pop_front();
        }
        self.snapshots.push_back((seq, state, now));
    }

    /// Look up a baseline by sequence number.
    pub fn get_baseline(&self, seq: BaselineSeq) -> Option<&T> {
        self.snapshots
            .iter()
            .rev()
            .find(|(s, _, _)| *s == seq)
            .map(|(_, state, _)| state)
    }

    /// Clear all stored baselines.
    pub fn reset(&mut self) {
        self.snapshots.clear();
    }

    /// Number of stored baselines.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the baseline buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

impl<T: Clone> BaselineManager<T> {
    /// Create a manager with config-driven parameters.
    pub fn from_config(config: &crate::NetworkConfig) -> Self {
        Self::new(config.max_baseline_snapshots, config.delta_baseline_timeout)
    }
}
