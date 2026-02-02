//! Snapshot interpolation for smooth client-side rendering.
//!
//! [`SnapshotBuffer`] stores timestamped snapshots and interpolates between
//! them at a configurable playback delay.

use std::collections::VecDeque;

/// Default number of snapshots to buffer before interpolation begins.
pub const DEFAULT_BUFFER_DEPTH: usize = 3;

/// Default playback delay in milliseconds behind the latest received snapshot.
pub const DEFAULT_PLAYBACK_DELAY_MS: f64 = 100.0;

/// Trait for types that support linear interpolation between two states.
pub trait Interpolatable: Clone {
    /// Linearly interpolate between `self` and `other` by factor `t` in `[0, 1]`.
    fn lerp(&self, other: &Self, t: f32) -> Self;
}

/// A timestamped snapshot for interpolation.
struct TimestampedSnapshot<T> {
    timestamp: f64,
    state: T,
}

/// Ring buffer of timestamped snapshots with interpolation sampling.
pub struct SnapshotBuffer<T: Interpolatable> {
    snapshots: VecDeque<TimestampedSnapshot<T>>,
    buffer_depth: usize,
    playback_delay_ms: f64,
}

impl<T: Interpolatable> SnapshotBuffer<T> {
    pub fn new() -> Self {
        Self {
            snapshots: VecDeque::new(),
            buffer_depth: DEFAULT_BUFFER_DEPTH,
            playback_delay_ms: DEFAULT_PLAYBACK_DELAY_MS,
        }
    }

    /// Create with custom buffer depth and playback delay.
    pub fn with_config(buffer_depth: usize, playback_delay_ms: f64) -> Self {
        Self {
            snapshots: VecDeque::new(),
            buffer_depth,
            playback_delay_ms,
        }
    }

    /// Push a new snapshot with its server timestamp (in milliseconds).
    pub fn push(&mut self, timestamp: f64, state: T) {
        // Maintain ordering — drop if older than newest
        if let Some(last) = self.snapshots.back() {
            if timestamp <= last.timestamp {
                return;
            }
        }

        self.snapshots
            .push_back(TimestampedSnapshot { timestamp, state });

        // Keep buffer bounded: retain enough for interpolation + some history
        let max_entries = self.buffer_depth * 2;
        while self.snapshots.len() > max_entries {
            self.snapshots.pop_front();
        }
    }

    /// Sample an interpolated state at `render_time` (in milliseconds).
    /// Returns `None` if insufficient snapshots are buffered.
    pub fn sample(&self, render_time: f64) -> Option<T> {
        let target_time = render_time - self.playback_delay_ms;

        if self.snapshots.len() < 2 {
            return None;
        }

        // Find the two snapshots that bracket target_time
        for i in 0..self.snapshots.len() - 1 {
            let a = &self.snapshots[i];
            let b = &self.snapshots[i + 1];

            if target_time >= a.timestamp && target_time <= b.timestamp {
                let duration = b.timestamp - a.timestamp;
                if duration <= 0.0 {
                    return Some(a.state.clone());
                }
                let t = ((target_time - a.timestamp) / duration) as f32;
                let t = t.clamp(0.0, 1.0);
                return Some(a.state.lerp(&b.state, t));
            }
        }

        // If target_time is beyond all snapshots, return the latest
        if target_time > self.snapshots.back().unwrap().timestamp {
            return Some(self.snapshots.back().unwrap().state.clone());
        }

        // If target_time is before all snapshots, return the oldest
        Some(self.snapshots.front().unwrap().state.clone())
    }

    /// Number of buffered snapshots.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Whether enough snapshots are buffered to begin interpolation.
    pub fn ready(&self) -> bool {
        self.snapshots.len() >= self.buffer_depth
    }

    /// Clear all buffered snapshots.
    pub fn reset(&mut self) {
        self.snapshots.clear();
    }

    /// Get the playback delay in milliseconds.
    pub fn playback_delay_ms(&self) -> f64 {
        self.playback_delay_ms
    }

    /// Set the playback delay in milliseconds.
    pub fn set_playback_delay_ms(&mut self, delay: f64) {
        self.playback_delay_ms = delay;
    }
}

impl<T: Interpolatable> Default for SnapshotBuffer<T> {
    fn default() -> Self {
        Self::new()
    }
}
