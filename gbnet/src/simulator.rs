//! Network condition simulator for testing: packet loss, latency, jitter,
//! duplicates, reordering, and bandwidth limiting.
use rand::Rng;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::config::SimulationConfig;

#[derive(Debug)]
struct DelayedPacket {
    data: Vec<u8>,
    addr: SocketAddr,
    deliver_at: Instant,
}

/// Simulates network conditions (loss, latency, jitter, duplicates, reordering).
#[derive(Debug)]
pub struct NetworkSimulator {
    config: SimulationConfig,
    delayed_packets: VecDeque<DelayedPacket>,
    token_bucket_tokens: f64,
    last_token_refill: Instant,
}

impl NetworkSimulator {
    pub fn new(config: SimulationConfig) -> Self {
        Self {
            config,
            delayed_packets: VecDeque::new(),
            token_bucket_tokens: 0.0,
            last_token_refill: Instant::now(),
        }
    }

    /// Process an outgoing packet through the simulator.
    /// Returns packets ready for immediate delivery, or buffers them for delayed delivery.
    pub fn process_send(&mut self, data: &[u8], addr: SocketAddr) -> Vec<(Vec<u8>, SocketAddr)> {
        let mut rng = rand::rng();
        let mut result = Vec::new();

        if self.config.packet_loss > 0.0 && rng.random::<f32>() < self.config.packet_loss {
            return result;
        }

        if self.config.bandwidth_limit_bytes_per_sec > 0 {
            self.refill_tokens();
            if self.token_bucket_tokens < data.len() as f64 {
                return result; // Over bandwidth
            }
            self.token_bucket_tokens -= data.len() as f64;
        }

        let base_latency = self.config.latency_ms as f64;
        let jitter = if self.config.jitter_ms > 0 {
            rng.random_range(0.0..self.config.jitter_ms as f64)
        } else {
            0.0
        };
        let delay_ms = base_latency + jitter;

        let extra = if self.config.out_of_order_chance > 0.0
            && rng.random::<f32>() < self.config.out_of_order_chance
        {
            rng.random_range(0.0..50.0)
        } else {
            0.0
        };

        let total_delay = Duration::from_millis((delay_ms + extra) as u64);
        let deliver_at = Instant::now() + total_delay;

        if total_delay.is_zero() {
            result.push((data.to_vec(), addr));
        } else {
            self.delayed_packets.push_back(DelayedPacket {
                data: data.to_vec(),
                addr,
                deliver_at,
            });
        }

        if self.config.duplicate_chance > 0.0 && rng.random::<f32>() < self.config.duplicate_chance
        {
            let dup_delay = Duration::from_millis((delay_ms + rng.random_range(0.0..20.0)) as u64);
            self.delayed_packets.push_back(DelayedPacket {
                data: data.to_vec(),
                addr,
                deliver_at: Instant::now() + dup_delay,
            });
        }

        result
    }

    /// Retrieve packets that are ready for delivery.
    pub fn receive_ready(&mut self) -> Vec<(Vec<u8>, SocketAddr)> {
        let now = Instant::now();
        let mut ready = Vec::new();

        while let Some(front) = self.delayed_packets.front() {
            if front.deliver_at <= now {
                let pkt = self.delayed_packets.pop_front().unwrap();
                ready.push((pkt.data, pkt.addr));
            } else {
                break;
            }
        }

        ready
    }

    fn refill_tokens(&mut self) {
        let elapsed = self.last_token_refill.elapsed().as_secs_f64();
        self.last_token_refill = Instant::now();
        self.token_bucket_tokens += elapsed * self.config.bandwidth_limit_bytes_per_sec as f64;
        let max = self.config.bandwidth_limit_bytes_per_sec as f64;
        if self.token_bucket_tokens > max {
            self.token_bucket_tokens = max;
        }
    }

    pub fn pending_count(&self) -> usize {
        self.delayed_packets.len()
    }
}

pub use crate::stats::{assess_connection_quality, ConnectionQuality};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    #[test]
    fn test_simulator_no_conditions() {
        let config = SimulationConfig::default();
        let mut sim = NetworkSimulator::new(config);

        let result = sim.process_send(b"hello", test_addr());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, b"hello");
    }

    #[test]
    fn test_simulator_packet_loss() {
        let config = SimulationConfig {
            packet_loss: 1.0, // 100% loss
            ..Default::default()
        };
        let mut sim = NetworkSimulator::new(config);

        let result = sim.process_send(b"hello", test_addr());
        assert!(result.is_empty());
    }

    #[test]
    fn test_simulator_latency() {
        let config = SimulationConfig {
            latency_ms: 50,
            ..Default::default()
        };
        let mut sim = NetworkSimulator::new(config);

        let result = sim.process_send(b"hello", test_addr());
        assert!(result.is_empty()); // Should be delayed

        assert_eq!(sim.pending_count(), 1);

        // After waiting, should be ready
        std::thread::sleep(Duration::from_millis(60));
        let ready = sim.receive_ready();
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn test_connection_quality_assessment() {
        assert_eq!(
            assess_connection_quality(50.0, 0.01),
            ConnectionQuality::Good
        );
        assert_eq!(
            assess_connection_quality(150.0, 0.05),
            ConnectionQuality::Fair
        );
        assert_eq!(
            assess_connection_quality(300.0, 0.2),
            ConnectionQuality::Poor
        );
    }

    #[test]
    fn test_simulator_handles_gracefully() {
        let config = SimulationConfig {
            packet_loss: 0.5,
            latency_ms: 10,
            jitter_ms: 5,
            duplicate_chance: 0.1,
            out_of_order_chance: 0.2,
            bandwidth_limit_bytes_per_sec: 10000,
        };
        let mut sim = NetworkSimulator::new(config);

        // Send many packets - should not panic
        for _ in 0..100 {
            let _ = sim.process_send(b"test data", test_addr());
        }

        std::thread::sleep(Duration::from_millis(20));
        let _ = sim.receive_ready();
    }
}
