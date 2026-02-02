//! Message fragmentation, reassembly, and path MTU discovery.
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DEFAULT_PROBE_TIMEOUT_MILLIS: u64 = 500;
pub const DEFAULT_MAX_PROBE_ATTEMPTS: u32 = 10;
pub const MIN_MTU: usize = 576;
pub const MAX_MTU: usize = 1500;
pub const MTU_CONVERGENCE_THRESHOLD: usize = 1;

/// Errors from the fragmentation subsystem.
#[derive(Debug)]
pub enum FragmentError {
    TooManyFragments,
}

impl std::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FragmentError::TooManyFragments => write!(
                f,
                "Message requires more than {} fragments",
                MAX_FRAGMENT_COUNT
            ),
        }
    }
}

impl std::error::Error for FragmentError {}

/// Fragment header: message_id (u32) + fragment_index (u8) + fragment_count (u8) = 6 bytes
pub const FRAGMENT_HEADER_SIZE: usize = 6;

#[derive(Debug, Clone)]
pub struct FragmentHeader {
    pub message_id: u32,
    pub fragment_index: u8,
    pub fragment_count: u8,
}

impl FragmentHeader {
    pub fn serialize(&self) -> [u8; FRAGMENT_HEADER_SIZE] {
        let id_bytes = self.message_id.to_be_bytes();
        [
            id_bytes[0],
            id_bytes[1],
            id_bytes[2],
            id_bytes[3],
            self.fragment_index,
            self.fragment_count,
        ]
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < FRAGMENT_HEADER_SIZE {
            return None;
        }
        Some(Self {
            message_id: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            fragment_index: data[4],
            fragment_count: data[5],
        })
    }
}

/// Splits a message into fragments.
/// Maximum number of fragments a message can be split into.
pub const MAX_FRAGMENT_COUNT: usize = 255;

/// Splits a message into fragments. Returns an error if the message requires too many fragments.
pub fn fragment_message(
    message_id: u32,
    data: &[u8],
    max_fragment_payload: usize,
) -> Result<Vec<Vec<u8>>, FragmentError> {
    if data.is_empty() || max_fragment_payload == 0 {
        return Ok(vec![]);
    }

    let fragment_count = data.len().div_ceil(max_fragment_payload);
    if fragment_count > MAX_FRAGMENT_COUNT {
        return Err(FragmentError::TooManyFragments);
    }
    let fragment_count = fragment_count as u8;

    let mut fragments = Vec::new();
    for i in 0..fragment_count {
        let start = i as usize * max_fragment_payload;
        let end = ((i as usize + 1) * max_fragment_payload).min(data.len());

        let header = FragmentHeader {
            message_id,
            fragment_index: i,
            fragment_count,
        };

        let mut fragment = Vec::with_capacity(FRAGMENT_HEADER_SIZE + (end - start));
        fragment.extend_from_slice(&header.serialize());
        fragment.extend_from_slice(&data[start..end]);
        fragments.push(fragment);
    }
    Ok(fragments)
}

/// Tracks fragments for a single message being reassembled.
#[derive(Debug)]
struct FragmentBuffer {
    fragments: Vec<Option<Vec<u8>>>,
    fragment_count: u8,
    received_count: u8,
    created_at: Instant,
    total_size: usize,
}

impl FragmentBuffer {
    fn new(fragment_count: u8) -> Self {
        let mut fragments = Vec::with_capacity(fragment_count as usize);
        for _ in 0..fragment_count {
            fragments.push(None);
        }
        Self {
            fragments,
            fragment_count,
            received_count: 0,
            created_at: Instant::now(),
            total_size: 0,
        }
    }

    fn insert(&mut self, index: u8, data: Vec<u8>) -> bool {
        if index >= self.fragment_count {
            return false;
        }
        let idx = index as usize;
        if self.fragments[idx].is_none() {
            self.total_size += data.len();
            self.received_count += 1;
            self.fragments[idx] = Some(data);
        }
        self.is_complete()
    }

    fn is_complete(&self) -> bool {
        self.received_count == self.fragment_count
    }

    fn assemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut result = Vec::with_capacity(self.total_size);
        for frag in &self.fragments {
            if let Some(data) = frag {
                result.extend_from_slice(data);
            } else {
                return None;
            }
        }
        Some(result)
    }
}

/// Reassembles fragmented messages.
#[derive(Debug)]
pub struct FragmentAssembler {
    buffers: HashMap<u32, FragmentBuffer>,
    timeout: Duration,
    max_buffer_size: usize,
    current_buffer_size: usize,
}

impl FragmentAssembler {
    pub fn new(timeout: Duration, max_buffer_size: usize) -> Self {
        Self {
            buffers: HashMap::new(),
            timeout,
            max_buffer_size,
            current_buffer_size: 0,
        }
    }

    /// Process a fragment. Returns the reassembled message if all fragments arrived.
    pub fn process_fragment(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.cleanup();

        let header = FragmentHeader::deserialize(data)?;
        let fragment_data = data[FRAGMENT_HEADER_SIZE..].to_vec();
        let fragment_size = fragment_data.len();

        if let Some(existing) = self.buffers.get(&header.message_id) {
            if existing.fragment_count != header.fragment_count {
                return None;
            }
        }

        if self.current_buffer_size + fragment_size > self.max_buffer_size {
            self.expire_oldest();
        }

        let buffer = self
            .buffers
            .entry(header.message_id)
            .or_insert_with(|| FragmentBuffer::new(header.fragment_count));

        self.current_buffer_size += fragment_size;

        if buffer.insert(header.fragment_index, fragment_data) {
            let result = buffer.assemble();
            if let Some(buf) = self.buffers.remove(&header.message_id) {
                self.current_buffer_size = self.current_buffer_size.saturating_sub(buf.total_size);
            }
            result
        } else {
            None
        }
    }

    /// Remove expired incomplete fragment buffers.
    pub fn cleanup(&mut self) {
        let timeout = self.timeout;
        let mut removed_size = 0;
        self.buffers.retain(|_, buf| {
            let keep = buf.created_at.elapsed() < timeout;
            if !keep {
                removed_size += buf.total_size;
            }
            keep
        });
        self.current_buffer_size = self.current_buffer_size.saturating_sub(removed_size);

        debug_assert_eq!(
            self.current_buffer_size,
            self.buffers.values().map(|b| b.total_size).sum::<usize>(),
            "Fragment buffer size tracking drifted"
        );
    }

    fn expire_oldest(&mut self) {
        if let Some(oldest_id) = self
            .buffers
            .iter()
            .min_by_key(|(_, buf)| buf.created_at)
            .map(|(id, _)| *id)
        {
            if let Some(buf) = self.buffers.remove(&oldest_id) {
                self.current_buffer_size = self.current_buffer_size.saturating_sub(buf.total_size);
            }
        }
    }
}

/// MTU discovery using binary search between min and max.
#[derive(Debug)]
pub struct MtuDiscovery {
    min_mtu: usize,
    max_mtu: usize,
    current_probe: usize,
    discovered_mtu: usize,
    state: MtuState,
    probe_timeout: Duration,
    last_probe_time: Option<Instant>,
    attempts: u32,
    max_attempts: u32,
}

#[derive(Debug, PartialEq)]
enum MtuState {
    Probing,
    Complete,
}

impl MtuDiscovery {
    pub fn new(min_mtu: usize, max_mtu: usize) -> Self {
        let initial_probe = (min_mtu + max_mtu) / 2;
        Self {
            min_mtu,
            max_mtu,
            current_probe: initial_probe,
            discovered_mtu: min_mtu, // Start with safe default
            state: MtuState::Probing,
            probe_timeout: Duration::from_millis(DEFAULT_PROBE_TIMEOUT_MILLIS),
            last_probe_time: None,
            attempts: 0,
            max_attempts: DEFAULT_MAX_PROBE_ATTEMPTS,
        }
    }

    pub fn default_discovery() -> Self {
        Self::new(MIN_MTU, MAX_MTU)
    }

    /// Get the next probe size to send, or None if discovery is complete.
    pub fn next_probe(&mut self) -> Option<usize> {
        if self.state == MtuState::Complete || self.attempts >= self.max_attempts {
            self.state = MtuState::Complete;
            return None;
        }

        if self.max_mtu - self.min_mtu <= MTU_CONVERGENCE_THRESHOLD {
            self.state = MtuState::Complete;
            return None;
        }

        if let Some(last) = self.last_probe_time {
            if last.elapsed() < self.probe_timeout {
                return None;
            }
        }

        self.current_probe = (self.min_mtu + self.max_mtu) / 2;
        self.last_probe_time = Some(Instant::now());
        self.attempts += 1;
        Some(self.current_probe)
    }

    /// Called when a probe of given size was successfully received.
    pub fn on_probe_success(&mut self, size: usize) {
        if size >= self.min_mtu {
            self.discovered_mtu = size;
            self.min_mtu = size;
        }
    }

    /// Called when a probe timed out (too large).
    pub fn on_probe_timeout(&mut self) {
        self.max_mtu = self.current_probe;
    }

    pub fn discovered_mtu(&self) -> usize {
        self.discovered_mtu
    }

    pub fn is_complete(&self) -> bool {
        self.state == MtuState::Complete
    }

    /// Check if the current probe has timed out without acknowledgement.
    /// If so, treat the current probe size as too large.
    pub fn check_probe_timeout(&mut self) {
        if self.state == MtuState::Complete {
            return;
        }
        if let Some(last) = self.last_probe_time {
            if last.elapsed() >= self.probe_timeout {
                self.on_probe_timeout();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_roundtrip() {
        let data = vec![42u8; 3000]; // 3KB message
        let fragments = fragment_message(1, &data, 1024).unwrap();

        assert_eq!(fragments.len(), 3);

        let mut assembler = FragmentAssembler::new(Duration::from_secs(5), 1024 * 1024);
        let mut result = None;
        for frag in &fragments {
            result = assembler.process_fragment(frag);
        }

        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_fragment_out_of_order() {
        let data = vec![0xABu8; 2500];
        let fragments = fragment_message(2, &data, 1024).unwrap();

        let mut assembler = FragmentAssembler::new(Duration::from_secs(5), 1024 * 1024);

        // Deliver out of order: last, first, middle
        assert!(assembler.process_fragment(&fragments[2]).is_none());
        assert!(assembler.process_fragment(&fragments[0]).is_none());
        let result = assembler.process_fragment(&fragments[1]);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_fragment_timeout_cleanup() {
        let mut assembler = FragmentAssembler::new(Duration::from_millis(1), 1024 * 1024);

        let data = vec![1u8; 2000];
        let fragments = fragment_message(1, &data, 1024).unwrap();

        // Only deliver first fragment
        assembler.process_fragment(&fragments[0]);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));
        assembler.cleanup();

        assert!(assembler.buffers.is_empty());
    }

    #[test]
    fn test_fragment_various_sizes() {
        for size in [1, 100, 1023, 1024, 1025, 5000, 10000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let fragments = fragment_message(0, &data, 1024).unwrap();

            let mut assembler = FragmentAssembler::new(Duration::from_secs(5), 1024 * 1024);
            let mut result = None;
            for frag in &fragments {
                result = assembler.process_fragment(frag);
            }

            let result = result.unwrap();
            assert_eq!(result.len(), data.len());
            assert_eq!(result, data);
        }
    }

    #[test]
    fn test_mtu_discovery_converges() {
        let mut mtu = MtuDiscovery::new(576, 1500);
        // Override probe timeout to zero for testing
        mtu.probe_timeout = Duration::from_millis(0);

        let real_mtu = 1200;
        for _ in 0..20 {
            if let Some(probe) = mtu.next_probe() {
                if probe <= real_mtu {
                    mtu.on_probe_success(probe);
                } else {
                    mtu.on_probe_timeout();
                }
            }
        }

        let discovered = mtu.discovered_mtu();
        assert!(
            (1100..=1200).contains(&discovered),
            "Discovered MTU {} should be near 1200",
            discovered
        );
    }

    #[test]
    fn test_fragment_header_serialize_deserialize() {
        let header = FragmentHeader {
            message_id: 12345,
            fragment_index: 3,
            fragment_count: 7,
        };

        let bytes = header.serialize();
        let parsed = FragmentHeader::deserialize(&bytes).unwrap();

        assert_eq!(parsed.message_id, 12345);
        assert_eq!(parsed.fragment_index, 3);
        assert_eq!(parsed.fragment_count, 7);
    }

    #[test]
    fn test_memory_limit_enforcement() {
        let mut assembler = FragmentAssembler::new(Duration::from_secs(60), 100);

        // Try to add fragments that exceed the memory limit
        let data = vec![0u8; 200];
        let fragments = fragment_message(1, &data, 50).unwrap();

        // Should handle gracefully (evict or reject)
        for frag in &fragments {
            let _ = assembler.process_fragment(frag);
        }
    }

    #[test]
    fn test_cleanup_before_budget_check() {
        // Verify that cleanup runs before the budget check in process_fragment
        // Use a multi-fragment message so the buffer entry persists after inserting one fragment
        let mut assembler = FragmentAssembler::new(Duration::from_millis(1), 200);

        // Add first fragment of a 2-fragment message for message 1
        let data1 = vec![0u8; 300];
        let frags1 = fragment_message(1, &data1, 200).unwrap();
        assert!(frags1.len() >= 2);
        assembler.process_fragment(&frags1[0]);
        assert!(assembler.buffers.contains_key(&1));

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        // Now adding a new fragment should succeed because stale entries are purged first
        let data2 = vec![1u8; 300];
        let frags2 = fragment_message(2, &data2, 200).unwrap();
        assembler.process_fragment(&frags2[0]);

        // The old entry should be gone, new one present
        assert!(!assembler.buffers.contains_key(&1));
        assert!(assembler.buffers.contains_key(&2));
    }
}
