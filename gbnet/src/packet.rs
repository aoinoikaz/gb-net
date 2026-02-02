//! Core packet structures and wire format for reliable UDP transport.
use crate::serialize::{
    bit_io::{BitBuffer, BitRead, BitWrite},
    BitDeserialize, BitSerialize,
};
use gbnet_macros::NetworkSerialize;
use std::io;

pub use crate::util::{sequence_diff, sequence_greater_than};

/// Fixed-size header present on every packet: protocol ID, sequence, ack, and ack bitfield.
#[derive(Debug, Clone, PartialEq, NetworkSerialize)]
pub struct PacketHeader {
    #[bits = 32]
    pub protocol_id: u32,
    #[bits = 16]
    pub sequence: u16,
    #[bits = 16]
    pub ack: u16,
    #[bits = 64]
    pub ack_bits: u64,
}

/// Discriminated packet type encoded in 4 bits (up to 16 variants).
#[derive(Debug, Clone, PartialEq, NetworkSerialize)]
#[bits = 4] // 16 packet types max
pub enum PacketType {
    ConnectionRequest,
    ConnectionChallenge {
        #[bits = 64]
        server_salt: u64,
    },
    ConnectionResponse {
        #[bits = 64]
        client_salt: u64,
    },
    ConnectionAccept,
    ConnectionDeny {
        #[bits = 8]
        reason: u8,
    },
    Disconnect {
        #[bits = 8]
        reason: u8,
    },
    KeepAlive,
    Payload {
        #[bits = 3]
        channel: u8,
        #[bits = 1]
        is_fragment: bool,
    },
    BatchedPayload {
        #[bits = 3]
        channel: u8,
    },
    MtuProbe {
        #[bits = 16]
        probe_size: u16,
    },
    MtuProbeAck {
        #[bits = 16]
        probe_size: u16,
    },
    AckOnly,
    ConnectionCookie {
        #[bits = 64]
        cookie_high: u64,
        #[bits = 64]
        cookie_low: u64,
    },
    ConnectionRequestWithCookie {
        #[bits = 64]
        cookie_high: u64,
        #[bits = 64]
        cookie_low: u64,
    },
}

/// A complete packet: header, type discriminant, and optional payload bytes.
#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Creates a packet with no payload.
    pub fn new(header: PacketHeader, packet_type: PacketType) -> Self {
        Self {
            header,
            packet_type,
            payload: Vec::new(),
        }
    }

    /// Attaches a payload to this packet (builder pattern).
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// Serializes the packet into a byte vector.
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut buffer = BitBuffer::new();

        self.header.bit_serialize(&mut buffer)?;
        self.packet_type.bit_serialize(&mut buffer)?;

        let padding = (8 - BitWrite::bit_pos(&buffer) % 8) % 8;
        if padding > 0 {
            buffer.write_bits(0, padding)?;
        }

        let header_bytes = buffer.into_bytes(true)?;
        let mut result = header_bytes;
        result.extend_from_slice(&self.payload);

        Ok(result)
    }

    /// Deserializes a packet from a byte slice.
    pub fn deserialize(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty packet"));
        }

        let mut buffer = BitBuffer::from_bytes(data.to_vec());

        let header = PacketHeader::bit_deserialize(&mut buffer)?;
        let packet_type = PacketType::bit_deserialize(&mut buffer)?;

        while !BitRead::bit_pos(&buffer).is_multiple_of(8) {
            buffer.read_bit()?;
        }

        let header_size = BitRead::bit_pos(&buffer) / 8;
        let payload = if header_size < data.len() {
            data[header_size..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            header,
            packet_type,
            payload,
        })
    }
}

/// Well-known disconnect reason codes sent in [`PacketType::Disconnect`].
pub mod disconnect_reason {
    pub const TIMEOUT: u8 = 0;
    pub const REQUESTED: u8 = 1;
    pub const KICKED: u8 = 2;
    pub const SERVER_FULL: u8 = 3;
    pub const PROTOCOL_MISMATCH: u8 = 4;
}

/// Well-known connection-deny reason codes sent in [`PacketType::ConnectionDeny`].
pub mod deny_reason {
    pub const SERVER_FULL: u8 = 0;
    pub const ALREADY_CONNECTED: u8 = 1;
    pub const INVALID_PROTOCOL: u8 = 2;
    pub const BANNED: u8 = 3;
    pub const INVALID_CHALLENGE: u8 = 4;
}
