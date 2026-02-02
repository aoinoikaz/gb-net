//! CRC32C integrity, connect-token authentication, rate limiting, and optional AES-256-GCM encryption.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::config::DEFAULT_MAX_TRACKED_TOKENS;

/// CRC-32C (Castagnoli) polynomial used for packet integrity (iSCSI standard).
const CRC32C_POLYNOMIAL: u32 = 0x82F63B78;

/// CRC32C checksum (Castagnoli) - used for packet integrity.
/// Uses the CRC-32C polynomial (iSCSI).
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32C_POLYNOMIAL;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Append CRC32C to packet data.
pub fn append_crc32(data: &mut Vec<u8>) {
    let crc = crc32c(data);
    data.extend_from_slice(&crc.to_le_bytes());
}

/// Validate and strip CRC32C from packet data. Returns None if corrupt.
pub fn validate_and_strip_crc32(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }
    let payload = &data[..data.len() - 4];
    let expected = u32::from_le_bytes([
        data[data.len() - 4],
        data[data.len() - 3],
        data[data.len() - 2],
        data[data.len() - 1],
    ]);
    let actual = crc32c(payload);
    if actual == expected {
        Some(payload)
    } else {
        None
    }
}

/// Connect token for netcode.io-style authentication.
#[derive(Debug, Clone)]
pub struct ConnectToken {
    pub client_id: u64,
    pub server_addresses: Vec<SocketAddr>,
    pub create_time: Instant,
    pub expire_duration: Duration,
    pub user_data: Vec<u8>,
    pub token_data: Vec<u8>,
}

impl ConnectToken {
    pub fn new(
        client_id: u64,
        server_addresses: Vec<SocketAddr>,
        expire_secs: u64,
        user_data: Vec<u8>,
    ) -> Self {
        let mut token_data = Vec::new();
        token_data.extend_from_slice(&client_id.to_le_bytes());
        token_data.extend_from_slice(&expire_secs.to_le_bytes());
        token_data.extend_from_slice(&(user_data.len() as u32).to_le_bytes());
        token_data.extend_from_slice(&user_data);

        Self {
            client_id,
            server_addresses,
            create_time: Instant::now(),
            expire_duration: Duration::from_secs(expire_secs),
            user_data,
            token_data,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.create_time.elapsed() > self.expire_duration
    }
}

/// Server-side connect token validator.
#[derive(Debug)]
pub struct TokenValidator {
    used_tokens: HashMap<u64, Instant>,
    token_lifetime: Duration,
    max_tracked_tokens: usize,
    tokens_evicted: u64,
}

impl TokenValidator {
    pub fn new(token_lifetime: Duration) -> Self {
        Self {
            used_tokens: HashMap::new(),
            token_lifetime,
            max_tracked_tokens: DEFAULT_MAX_TRACKED_TOKENS,
            tokens_evicted: 0,
        }
    }

    pub fn with_max_tracked_tokens(mut self, max: usize) -> Self {
        self.max_tracked_tokens = max;
        self
    }

    /// Validate a connect token. Returns client_id if valid.
    pub fn validate(&mut self, token: &ConnectToken) -> Result<u64, TokenError> {
        if token.is_expired() {
            return Err(TokenError::Expired);
        }

        if self.used_tokens.contains_key(&token.client_id) {
            return Err(TokenError::Replayed);
        }

        self.used_tokens.insert(token.client_id, Instant::now());

        if self.used_tokens.len() > self.max_tracked_tokens {
            self.cleanup();

            while self.used_tokens.len() > self.max_tracked_tokens {
                let oldest_key = self
                    .used_tokens
                    .iter()
                    .min_by_key(|(_, instant)| **instant)
                    .map(|(&k, _)| k);
                if let Some(key) = oldest_key {
                    self.used_tokens.remove(&key);
                    self.tokens_evicted += 1;
                } else {
                    break;
                }
            }
        }

        Ok(token.client_id)
    }

    fn cleanup(&mut self) {
        let lifetime = self.token_lifetime;
        self.used_tokens
            .retain(|_, created| created.elapsed() < lifetime);
    }

    pub fn tokens_evicted(&self) -> u64 {
        self.tokens_evicted
    }
}

/// Errors returned when validating a connect token.
#[derive(Debug)]
pub enum TokenError {
    Expired,
    Replayed,
    Invalid,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Expired => write!(f, "Token expired"),
            TokenError::Replayed => write!(f, "Token replayed"),
            TokenError::Invalid => write!(f, "Invalid token"),
        }
    }
}

impl std::error::Error for TokenError {}

/// Rate limiter for connection requests per source IP.
/// Keys on IP address (not socket address) to prevent port-rotation bypass.
#[derive(Debug)]
pub struct ConnectionRateLimiter {
    requests: HashMap<IpAddr, Vec<Instant>>,
    max_requests_per_second: usize,
    window: Duration,
}

impl ConnectionRateLimiter {
    pub fn new(max_requests_per_second: usize) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests_per_second,
            window: Duration::from_secs(1),
        }
    }

    /// Returns true if the request should be allowed.
    pub fn allow(&mut self, addr: SocketAddr) -> bool {
        let now = Instant::now();
        let window = self.window;

        let timestamps = self.requests.entry(addr.ip()).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= self.max_requests_per_second {
            false
        } else {
            timestamps.push(now);
            true
        }
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = self.window;
        self.requests.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) < window);
            !timestamps.is_empty()
        });
    }
}

/// Cookie size in bytes for stateless connection cookies.
pub const COOKIE_SIZE: usize = 16;

/// Generate a stateless cookie from client address, timestamp, and server secret.
/// Uses a CRC32C chain to produce a 16-byte cookie without additional dependencies.
pub fn generate_cookie(
    addr: &SocketAddr,
    timestamp_secs: u64,
    secret: &[u8; 32],
) -> [u8; COOKIE_SIZE] {
    let mut data = Vec::new();
    match addr.ip() {
        IpAddr::V4(ip) => data.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => data.extend_from_slice(&ip.octets()),
    }
    data.extend_from_slice(&addr.port().to_le_bytes());
    data.extend_from_slice(&timestamp_secs.to_le_bytes());
    data.extend_from_slice(&secret[..16]);

    let c0 = crc32c(&data);
    data.extend_from_slice(&c0.to_le_bytes());
    data.extend_from_slice(&secret[16..32]);
    let c1 = crc32c(&data);

    data.extend_from_slice(&c1.to_le_bytes());
    let c2 = crc32c(&data);

    data.extend_from_slice(&c2.to_le_bytes());
    let c3 = crc32c(&data);

    let mut cookie = [0u8; COOKIE_SIZE];
    cookie[0..4].copy_from_slice(&c0.to_le_bytes());
    cookie[4..8].copy_from_slice(&c1.to_le_bytes());
    cookie[8..12].copy_from_slice(&c2.to_le_bytes());
    cookie[12..16].copy_from_slice(&c3.to_le_bytes());
    cookie
}

/// Validate a stateless cookie against the expected value for an address.
/// Checks the current timestamp window and one previous window to handle clock skew.
pub fn validate_cookie(
    cookie: &[u8; COOKIE_SIZE],
    addr: &SocketAddr,
    current_timestamp_secs: u64,
    secret: &[u8; 32],
    window_secs: u64,
) -> bool {
    // Check current window
    let current_window = current_timestamp_secs / window_secs;
    let expected = generate_cookie(addr, current_window, secret);
    if cookie == &expected {
        return true;
    }
    // Check previous window for clock skew tolerance
    if current_window > 0 {
        let prev_expected = generate_cookie(addr, current_window - 1, secret);
        if cookie == &prev_expected {
            return true;
        }
    }
    false
}

/// Convert a 16-byte cookie into (high, low) u64 pair for wire encoding.
pub fn cookie_to_u64_pair(cookie: &[u8; COOKIE_SIZE]) -> (u64, u64) {
    let high = u64::from_le_bytes(cookie[0..8].try_into().unwrap());
    let low = u64::from_le_bytes(cookie[8..16].try_into().unwrap());
    (high, low)
}

/// Convert (high, low) u64 pair back into a 16-byte cookie.
pub fn cookie_from_u64_pair(high: u64, low: u64) -> [u8; COOKIE_SIZE] {
    let mut cookie = [0u8; COOKIE_SIZE];
    cookie[0..8].copy_from_slice(&high.to_le_bytes());
    cookie[8..16].copy_from_slice(&low.to_le_bytes());
    cookie
}

/// AES-256-GCM authenticated encryption (requires `encryption` feature).
/// Nonce is derived from the packet sequence number for replay protection.
#[cfg(feature = "encryption")]
pub struct EncryptionState {
    key: ring::aead::LessSafeKey,
    connection_salt: u64,
}

#[cfg(feature = "encryption")]
const AES_GCM_TAG_LEN: usize = 16;
#[cfg(feature = "encryption")]
const AES_GCM_NONCE_LEN: usize = 12;

#[cfg(feature = "encryption")]
impl EncryptionState {
    /// Create a new encryption state from a 32-byte key.
    pub fn new(key_bytes: &[u8; 32]) -> Result<Self, EncryptionError> {
        let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_bytes)
            .map_err(|_| EncryptionError::InvalidKey)?;
        Ok(Self {
            key: ring::aead::LessSafeKey::new(unbound),
            connection_salt: 0,
        })
    }

    /// Set the connection salt (should be `client_salt ^ server_salt` after handshake).
    pub fn set_connection_salt(&mut self, salt: u64) {
        self.connection_salt = salt;
    }

    /// Encrypt payload using AES-256-GCM with sequence-derived nonce.
    pub fn encrypt(&self, payload: &[u8], sequence: u64) -> Result<Vec<u8>, EncryptionError> {
        let nonce = self.make_nonce(sequence);
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| EncryptionError::NonceError)?;

        let mut in_out = payload.to_vec();
        in_out.reserve(AES_GCM_TAG_LEN);

        self.key
            .seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut in_out)
            .map_err(|_| EncryptionError::EncryptFailed)?;

        Ok(in_out)
    }

    /// Decrypt payload using AES-256-GCM with sequence-derived nonce.
    pub fn decrypt(&self, ciphertext: &[u8], sequence: u64) -> Result<Vec<u8>, EncryptionError> {
        if ciphertext.len() < AES_GCM_TAG_LEN {
            return Err(EncryptionError::DecryptFailed);
        }

        let nonce = self.make_nonce(sequence);
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| EncryptionError::NonceError)?;

        let mut in_out = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, ring::aead::Aad::empty(), &mut in_out)
            .map_err(|_| EncryptionError::DecryptFailed)?;

        Ok(plaintext.to_vec())
    }

    fn make_nonce(&self, sequence: u64) -> [u8; AES_GCM_NONCE_LEN] {
        let mut nonce = [0u8; AES_GCM_NONCE_LEN];
        // XOR full 8-byte salt with 8-byte sequence for nonce bytes [0..8],
        // using all 64 bits of salt entropy. Bytes [8..12] remain zero for
        // domain separation.
        let xored = sequence ^ self.connection_salt;
        nonce[..8].copy_from_slice(&xored.to_le_bytes());
        nonce
    }
}

#[cfg(feature = "encryption")]
impl std::fmt::Debug for EncryptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionState")
            .field("algorithm", &"AES-256-GCM")
            .finish()
    }
}

/// Errors from the AES-256-GCM encryption subsystem.
#[derive(Debug)]
pub enum EncryptionError {
    InvalidKey,
    NonceError,
    EncryptFailed,
    DecryptFailed,
    #[cfg(not(feature = "encryption"))]
    FeatureNotEnabled,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionError::InvalidKey => write!(f, "Invalid encryption key"),
            EncryptionError::NonceError => write!(f, "Nonce generation error"),
            EncryptionError::EncryptFailed => write!(f, "Encryption failed"),
            EncryptionError::DecryptFailed => write!(f, "Decryption failed (authentication)"),
            #[cfg(not(feature = "encryption"))]
            EncryptionError::FeatureNotEnabled => {
                write!(f, "Encryption feature not enabled")
            }
        }
    }
}

impl std::error::Error for EncryptionError {}

/// Stub for when the encryption feature is not enabled.
#[cfg(not(feature = "encryption"))]
pub fn encrypt_payload(
    _payload: &[u8],
    _key: &[u8; 32],
    _sequence: u64,
) -> Result<Vec<u8>, EncryptionError> {
    Err(EncryptionError::FeatureNotEnabled)
}

/// Stub for when the encryption feature is not enabled.
#[cfg(not(feature = "encryption"))]
pub fn decrypt_payload(
    _ciphertext: &[u8],
    _key: &[u8; 32],
    _sequence: u64,
) -> Result<Vec<u8>, EncryptionError> {
    Err(EncryptionError::FeatureNotEnabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_crc32_catches_bitflips() {
        let data = b"hello world".to_vec();
        let crc = crc32c(&data);

        // Same data should produce same CRC
        assert_eq!(crc, crc32c(&data));

        // Flipped bit should produce different CRC
        let mut corrupted = data.clone();
        corrupted[0] ^= 1;
        assert_ne!(crc, crc32c(&corrupted));
    }

    #[test]
    fn test_crc32_append_and_validate() {
        let mut data = b"test packet data".to_vec();
        append_crc32(&mut data);

        assert!(data.len() == 16 + 4);
        let validated = validate_and_strip_crc32(&data);
        assert!(validated.is_some());
        assert_eq!(validated.unwrap(), b"test packet data");
    }

    #[test]
    fn test_crc32_corrupted_rejected() {
        let mut data = b"test packet data".to_vec();
        append_crc32(&mut data);

        // Corrupt a byte
        data[5] ^= 0xFF;
        assert!(validate_and_strip_crc32(&data).is_none());
    }

    #[test]
    fn test_connect_token_expiry() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let token = ConnectToken {
            client_id: 42,
            server_addresses: vec![addr],
            create_time: Instant::now() - Duration::from_secs(10),
            expire_duration: Duration::from_secs(5),
            user_data: vec![],
            token_data: vec![],
        };
        assert!(token.is_expired());

        let fresh_token = ConnectToken::new(42, vec![addr], 60, vec![]);
        assert!(!fresh_token.is_expired());
    }

    #[test]
    fn test_token_replay_rejection() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let mut validator = TokenValidator::new(Duration::from_secs(60));

        let token = ConnectToken::new(42, vec![addr], 60, vec![]);
        assert!(validator.validate(&token).is_ok());
        assert!(matches!(
            validator.validate(&token),
            Err(TokenError::Replayed)
        ));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_encryption_roundtrip() {
        let key = [0x42u8; 32];
        let payload = b"secret game data";
        let seq = 12345u64;

        let state = super::EncryptionState::new(&key).unwrap();
        let encrypted = state.encrypt(payload, seq).unwrap();
        assert_ne!(&encrypted[..payload.len()], &payload[..]);

        let decrypted = state.decrypt(&encrypted, seq).unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_replay_prevention_different_sequence() {
        let key = [0x42u8; 32];
        let payload = b"secret data";

        let state = super::EncryptionState::new(&key).unwrap();
        let enc1 = state.encrypt(payload, 1).unwrap();
        let enc2 = state.encrypt(payload, 2).unwrap();
        assert_ne!(enc1, enc2);

        // Decrypting with wrong sequence fails (authentication error)
        assert!(state.decrypt(&enc1, 2).is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = ConnectionRateLimiter::new(3);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);

        assert!(limiter.allow(addr));
        assert!(limiter.allow(addr));
        assert!(limiter.allow(addr));
        assert!(!limiter.allow(addr)); // 4th request blocked
    }

    #[test]
    fn test_token_table_bounded() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let mut validator =
            TokenValidator::new(Duration::from_secs(60)).with_max_tracked_tokens(10);

        // Insert more than max_tracked_tokens
        for i in 0..20u64 {
            let token = ConnectToken::new(i, vec![addr], 60, vec![]);
            let _ = validator.validate(&token);
        }

        // Should be bounded
        assert!(validator.used_tokens.len() <= 10);
        assert!(validator.tokens_evicted() > 0);
    }
}
