//! Binary congestion control (Gaffer-style Good/Bad modes), byte-budget gating,
//! adaptive recovery timer, message batching, and bandwidth tracking.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const CONGESTION_RATE_REDUCTION: f32 = 0.5;
pub const MIN_SEND_RATE: f32 = 1.0;
pub const BATCH_HEADER_SIZE: usize = 1;
pub const BATCH_LENGTH_SIZE: usize = 2;
pub const MAX_BATCH_MESSAGES: u8 = 255;

pub const INITIAL_CWND_PACKETS: usize = 10;
pub const MIN_CWND_BYTES: usize = 1200;

pub const MIN_RECOVERY_SECS: f64 = 1.0;
pub const MAX_RECOVERY_SECS: f64 = 60.0;
pub const RECOVERY_HALVE_INTERVAL_SECS: f64 = 10.0;
pub const QUICK_DROP_THRESHOLD_SECS: f64 = 10.0;

/// Phase for window-based congestion control.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionPhase {
    SlowStart,
    Avoidance,
    Recovery,
}

/// Binary congestion state: either network conditions are acceptable or degraded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionMode {
    Good,
    Bad,
}

/// Binary congestion controller inspired by Gaffer on Games.
#[derive(Debug)]
pub struct CongestionController {
    mode: CongestionMode,
    good_conditions_start: Option<Instant>,
    loss_threshold: f32,
    rtt_threshold_ms: f32,
    base_send_rate: f32,
    current_send_rate: f32,

    budget_bytes_remaining: i64,
    bytes_per_tick: usize,

    adaptive_recovery_secs: f64,
    last_good_entry: Option<Instant>,
    last_bad_entry: Option<Instant>,
}

impl CongestionController {
    pub fn new(
        base_send_rate: f32,
        loss_threshold: f32,
        rtt_threshold_ms: f32,
        recovery_time: Duration,
    ) -> Self {
        let recovery_secs = recovery_time.as_secs_f64();
        Self {
            mode: CongestionMode::Good,
            good_conditions_start: None,
            loss_threshold,
            rtt_threshold_ms,
            base_send_rate,
            current_send_rate: base_send_rate,
            budget_bytes_remaining: 0,
            bytes_per_tick: 0,
            adaptive_recovery_secs: recovery_secs,
            last_good_entry: None,
            last_bad_entry: None,
        }
    }

    /// Refill the byte budget at the start of each tick.
    pub fn refill_budget(&mut self, mtu: usize) {
        self.bytes_per_tick = (self.current_send_rate * mtu as f32) as usize;
        self.budget_bytes_remaining = self.bytes_per_tick as i64;
    }

    /// Deduct bytes from the send budget after queuing a packet.
    pub fn deduct_budget(&mut self, bytes: usize) {
        self.budget_bytes_remaining -= bytes as i64;
    }

    /// Update congestion state based on current network conditions.
    pub fn update(&mut self, packet_loss: f32, rtt_ms: f32) {
        let is_bad = packet_loss > self.loss_threshold || rtt_ms > self.rtt_threshold_ms;

        match self.mode {
            CongestionMode::Good => {
                if is_bad {
                    // Quick re-entry to Bad doubles recovery timer
                    if let Some(good_entry) = self.last_good_entry {
                        if good_entry.elapsed().as_secs_f64() < QUICK_DROP_THRESHOLD_SECS {
                            self.adaptive_recovery_secs =
                                (self.adaptive_recovery_secs * 2.0).min(MAX_RECOVERY_SECS);
                        }
                    }

                    self.mode = CongestionMode::Bad;
                    self.last_bad_entry = Some(Instant::now());
                    self.current_send_rate =
                        (self.base_send_rate * CONGESTION_RATE_REDUCTION).max(MIN_SEND_RATE);
                    self.good_conditions_start = None;
                } else if let Some(good_entry) = self.last_good_entry {
                    let elapsed = good_entry.elapsed().as_secs_f64();
                    let intervals = (elapsed / RECOVERY_HALVE_INTERVAL_SECS).floor() as u32;
                    if intervals > 0 {
                        for _ in 0..intervals {
                            self.adaptive_recovery_secs =
                                (self.adaptive_recovery_secs / 2.0).max(MIN_RECOVERY_SECS);
                        }
                        self.last_good_entry = Some(Instant::now());
                    }
                }
            }
            CongestionMode::Bad => {
                if !is_bad {
                    match self.good_conditions_start {
                        None => {
                            self.good_conditions_start = Some(Instant::now());
                        }
                        Some(start) => {
                            let required = Duration::from_secs_f64(self.adaptive_recovery_secs);
                            if start.elapsed() >= required {
                                self.mode = CongestionMode::Good;
                                self.last_good_entry = Some(Instant::now());
                                self.current_send_rate = self.base_send_rate;
                                self.good_conditions_start = None;
                            }
                        }
                    }
                } else {
                    self.good_conditions_start = None;
                }
            }
        }
    }

    pub fn mode(&self) -> CongestionMode {
        self.mode
    }

    pub fn send_rate(&self) -> f32 {
        self.current_send_rate
    }

    pub fn adaptive_recovery_secs(&self) -> f64 {
        self.adaptive_recovery_secs
    }

    /// Returns true if a packet can be sent given the number of packets
    /// already sent this update cycle and the packet's byte size.
    /// Checks both packet count and byte budget.
    pub fn can_send(&self, packets_sent_this_cycle: u32, packet_bytes: usize) -> bool {
        (packets_sent_this_cycle as f32) < self.current_send_rate
            && self.budget_bytes_remaining >= packet_bytes as i64
    }
}

/// Window-based congestion controller with slow start, avoidance, and recovery phases.
#[derive(Debug)]
pub struct CongestionWindow {
    phase: CongestionPhase,
    cwnd: f64,
    ssthresh: f64,
    bytes_in_flight: u64,
    mtu: usize,
    last_send_time: Option<Instant>,
    min_inter_packet_delay: Duration,
}

impl CongestionWindow {
    pub fn new(mtu: usize) -> Self {
        Self {
            phase: CongestionPhase::SlowStart,
            cwnd: (INITIAL_CWND_PACKETS * mtu) as f64,
            ssthresh: f64::MAX,
            bytes_in_flight: 0,
            mtu,
            last_send_time: None,
            min_inter_packet_delay: Duration::ZERO,
        }
    }

    /// Called when bytes are acknowledged.
    pub fn on_ack(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes as u64);
        match self.phase {
            CongestionPhase::SlowStart => {
                self.cwnd += bytes as f64;
                if self.cwnd >= self.ssthresh {
                    self.phase = CongestionPhase::Avoidance;
                }
            }
            CongestionPhase::Avoidance => {
                // Additive increase: cwnd += mtu * bytes / cwnd
                self.cwnd += (self.mtu as f64) * (bytes as f64) / self.cwnd;
            }
            CongestionPhase::Recovery => {
                // In recovery, be conservative
            }
        }
    }

    /// Called on packet loss detection.
    pub fn on_loss(&mut self) {
        self.ssthresh = self.cwnd / 2.0;
        if self.ssthresh < MIN_CWND_BYTES as f64 {
            self.ssthresh = MIN_CWND_BYTES as f64;
        }
        self.cwnd = self.ssthresh;
        self.phase = CongestionPhase::Recovery;
    }

    /// Exit recovery and return to avoidance.
    pub fn exit_recovery(&mut self) {
        if self.phase == CongestionPhase::Recovery {
            self.phase = CongestionPhase::Avoidance;
        }
    }

    /// Record bytes sent.
    pub fn on_send(&mut self, bytes: usize) {
        self.bytes_in_flight += bytes as u64;
        self.last_send_time = Some(Instant::now());
    }

    /// Returns true if a packet of the given size can be sent.
    pub fn can_send(&self, packet_bytes: usize) -> bool {
        self.bytes_in_flight + packet_bytes as u64 <= self.cwnd as u64
    }

    /// Update pacing delay from cwnd and RTT.
    pub fn update_pacing(&mut self, rtt: Duration) {
        if self.cwnd > 0.0 && !rtt.is_zero() {
            let packets_in_window = self.cwnd / self.mtu as f64;
            if packets_in_window > 0.0 {
                self.min_inter_packet_delay =
                    Duration::from_secs_f64(rtt.as_secs_f64() / packets_in_window);
            }
        }
    }

    /// Returns true if enough time has elapsed since the last send for pacing.
    pub fn can_send_paced(&self, now: Instant) -> bool {
        match self.last_send_time {
            Some(last) => now.duration_since(last) >= self.min_inter_packet_delay,
            None => true,
        }
    }

    pub fn phase(&self) -> CongestionPhase {
        self.phase
    }

    pub fn cwnd(&self) -> f64 {
        self.cwnd
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }
}

/// Packs multiple small messages into a single UDP packet up to MTU.
/// Wire format: [u8 message_count][u16 len][data]...
pub fn batch_messages(messages: &[Vec<u8>], max_size: usize) -> Vec<Vec<u8>> {
    let mut batches = Vec::new();
    let mut current_batch = Vec::new();
    let mut current_size = BATCH_HEADER_SIZE;
    let mut msg_count: u8 = 0;

    for msg in messages {
        let msg_wire_size = BATCH_LENGTH_SIZE + msg.len();
        if current_size + msg_wire_size > max_size && msg_count > 0 {
            let mut batch = Vec::with_capacity(current_size);
            batch.push(msg_count);
            batch.extend_from_slice(&current_batch);
            batches.push(batch);

            current_batch.clear();
            current_size = BATCH_HEADER_SIZE;
            msg_count = 0;
        }

        let len = msg.len() as u16;
        current_batch.extend_from_slice(&len.to_be_bytes());
        current_batch.extend_from_slice(msg);
        current_size += msg_wire_size;
        msg_count += 1;

        if msg_count == MAX_BATCH_MESSAGES {
            let mut batch = Vec::with_capacity(current_size);
            batch.push(msg_count);
            batch.extend_from_slice(&current_batch);
            batches.push(batch);

            current_batch.clear();
            current_size = BATCH_HEADER_SIZE;
            msg_count = 0;
        }
    }

    if msg_count > 0 {
        let mut batch = Vec::with_capacity(current_size);
        batch.push(msg_count);
        batch.extend_from_slice(&current_batch);
        batches.push(batch);
    }

    batches
}

/// Unbatch a batched packet into individual messages.
pub fn unbatch_messages(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.is_empty() {
        return None;
    }

    let msg_count = data[0] as usize;
    let mut messages = Vec::with_capacity(msg_count);
    let mut offset = 1;

    for _ in 0..msg_count {
        if offset + 2 > data.len() {
            return None;
        }
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + len > data.len() {
            return None;
        }
        messages.push(data[offset..offset + len].to_vec());
        offset += len;
    }

    Some(messages)
}

/// Bandwidth tracker using a sliding window backed by a `VecDeque`
/// to avoid unbounded growth.
#[derive(Debug)]
pub struct BandwidthTracker {
    window: VecDeque<(Instant, usize)>,
    window_duration: Duration,
}

impl BandwidthTracker {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            window: VecDeque::new(),
            window_duration,
        }
    }

    pub fn record(&mut self, bytes: usize) {
        self.window.push_back((Instant::now(), bytes));
        self.cleanup();
    }

    pub fn bytes_per_second(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let total_bytes: usize = self.window.iter().map(|(_, b)| b).sum();
        let elapsed = self.window_duration.as_secs_f64();
        if elapsed > 0.0 {
            total_bytes as f64 / elapsed
        } else {
            0.0
        }
    }

    fn cleanup(&mut self) {
        let cutoff = self.window_duration;
        while let Some(&(t, _)) = self.window.front() {
            if t.elapsed() >= cutoff {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_mode_transition() {
        let mut cc = CongestionController::new(60.0, 0.1, 250.0, Duration::from_millis(100));

        assert_eq!(cc.mode(), CongestionMode::Good);
        assert_eq!(cc.send_rate(), 60.0);

        // Bad conditions
        cc.update(0.2, 100.0);
        assert_eq!(cc.mode(), CongestionMode::Bad);
        assert_eq!(cc.send_rate(), 30.0);

        // Good conditions but not long enough
        cc.update(0.01, 50.0);
        assert_eq!(cc.mode(), CongestionMode::Bad);

        // Wait for recovery
        std::thread::sleep(Duration::from_millis(150));
        cc.update(0.01, 50.0);
        assert_eq!(cc.mode(), CongestionMode::Good);
        assert_eq!(cc.send_rate(), 60.0);
    }

    #[test]
    fn test_batch_unbatch_roundtrip() {
        let messages = vec![b"hello".to_vec(), b"world".to_vec(), b"test".to_vec()];

        let batches = batch_messages(&messages, 1200);
        assert_eq!(batches.len(), 1);

        let unbatched = unbatch_messages(&batches[0]).unwrap();
        assert_eq!(unbatched, messages);
    }

    #[test]
    fn test_batch_splits_at_mtu() {
        let messages: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; 200]).collect();
        let batches = batch_messages(&messages, 500);
        assert!(batches.len() > 1);

        // Verify all messages are preserved
        let mut total = 0;
        for batch in &batches {
            total += unbatch_messages(batch).unwrap().len();
        }
        assert_eq!(total, 10);
    }

    #[test]
    fn test_can_send_respects_rate_and_budget() {
        let mut cc = CongestionController::new(60.0, 0.1, 250.0, Duration::from_secs(10));
        cc.refill_budget(1200);

        assert!(cc.can_send(0, 1200));
        assert!(cc.can_send(59, 1200));
        assert!(!cc.can_send(60, 1200));

        // Exhaust budget
        for _ in 0..60 {
            cc.deduct_budget(1200);
        }
        assert!(!cc.can_send(0, 1200));
    }

    #[test]
    fn test_bandwidth_tracker() {
        let mut tracker = BandwidthTracker::new(Duration::from_secs(1));
        tracker.record(1000);
        tracker.record(2000);
        assert!(tracker.bytes_per_second() > 0.0);
    }

    #[test]
    fn test_byte_budget_depletes_and_replenishes() {
        let mut cc = CongestionController::new(60.0, 0.1, 250.0, Duration::from_secs(10));
        cc.refill_budget(1200);

        let initial = cc.budget_bytes_remaining;
        cc.deduct_budget(1200);
        assert_eq!(cc.budget_bytes_remaining, initial - 1200);

        // Refill
        cc.refill_budget(1200);
        assert_eq!(cc.budget_bytes_remaining, initial);
    }

    #[test]
    fn test_adaptive_recovery_doubles_on_quick_drop() {
        let mut cc = CongestionController::new(60.0, 0.1, 250.0, Duration::from_millis(50));

        let initial_recovery = cc.adaptive_recovery_secs();

        // Go to bad
        cc.update(0.2, 100.0);
        assert_eq!(cc.mode(), CongestionMode::Bad);

        // Recover quickly
        std::thread::sleep(Duration::from_millis(60));
        cc.update(0.01, 50.0); // start good timer
        std::thread::sleep(Duration::from_millis(60));
        cc.update(0.01, 50.0); // should recover
        assert_eq!(cc.mode(), CongestionMode::Good);

        // Drop back to bad quickly (within 10s)
        cc.update(0.2, 100.0);
        assert_eq!(cc.mode(), CongestionMode::Bad);

        // Recovery time should have doubled
        assert!(cc.adaptive_recovery_secs() > initial_recovery);
    }
}
