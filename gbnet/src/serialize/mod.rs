//! Bitpacked serialization for network messages.
//!
//! Provides [`BitBuffer`] for sub-byte serialization, the [`BitSerialize`] and
//! [`BitDeserialize`] traits, and the `#[derive(NetworkSerialize)]` proc macro
//! with `#[bits = N]` field attributes.

use byteorder::{ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

mod collections;
mod primitives;

pub mod bit_io {
    use log::{debug, trace};
    use std::io;

    /// Trait for writing individual bits and bit-packed values.
    pub trait BitWrite {
        fn write_bit(&mut self, bit: bool) -> io::Result<()>;
        fn write_bits(&mut self, value: u64, bits: usize) -> io::Result<()>;
        fn bit_pos(&self) -> usize;
    }

    /// Trait for reading individual bits and bit-packed values.
    pub trait BitRead {
        fn read_bit(&mut self) -> io::Result<bool>;
        fn read_bits(&mut self, bits: usize) -> io::Result<u64>;
        fn bit_pos(&self) -> usize;
    }

    /// Bit-level read/write buffer for sub-byte serialization, with optional measure-only mode.
    pub struct BitBuffer {
        buffer: Vec<u8>,
        bit_pos: usize,
        read_pos: usize,
        unpadded_length: usize,
        measure_only: bool,
    }

    impl Default for BitBuffer {
        fn default() -> Self {
            Self::new()
        }
    }

    impl BitBuffer {
        pub fn new() -> Self {
            BitBuffer {
                buffer: Vec::new(),
                bit_pos: 0,
                read_pos: 0,
                unpadded_length: 0,
                measure_only: false,
            }
        }

        /// Create a measure-only buffer that tracks serialized size without allocation.
        pub fn measure() -> Self {
            BitBuffer {
                buffer: Vec::new(),
                bit_pos: 0,
                read_pos: 0,
                unpadded_length: 0,
                measure_only: true,
            }
        }

        /// Returns the serialized size in bits.
        pub fn serialized_size_bits(&self) -> usize {
            self.unpadded_length
        }

        /// Returns the serialized size in bytes (rounded up).
        pub fn serialized_size_bytes(&self) -> usize {
            self.unpadded_length.div_ceil(8)
        }

        pub fn is_measure_only(&self) -> bool {
            self.measure_only
        }

        pub fn unpadded_length(&self) -> usize {
            self.unpadded_length
        }

        pub fn into_bytes(mut self, pad_to_byte: bool) -> io::Result<Vec<u8>> {
            self.flush(pad_to_byte)?;
            Ok(self.buffer)
        }

        pub fn from_bytes(bytes: Vec<u8>) -> Self {
            BitBuffer {
                buffer: bytes,
                bit_pos: 0,
                read_pos: 0,
                unpadded_length: 0,
                measure_only: false,
            }
        }

        pub fn to_bit_string(&self, bit_length: usize) -> String {
            let mut bit_string = String::new();
            let mut bits_written = 0;
            for (i, &byte) in self.buffer.iter().enumerate() {
                for j in (0..8).rev() {
                    if bits_written < bit_length {
                        let bit = (byte >> j) & 1;
                        bit_string.push_str(&bit.to_string());
                        bits_written += 1;
                    } else {
                        break;
                    }
                }
                if bits_written < bit_length && i < self.buffer.len() - 1 {
                    bit_string.push(' ');
                }
            }
            bit_string.trim().to_string()
        }

        fn flush(&mut self, pad_to_byte: bool) -> io::Result<()> {
            if pad_to_byte {
                while !self.bit_pos.is_multiple_of(8) {
                    self.write_bit(false)?;
                }
            }
            Ok(())
        }

        fn write_bytes_fast(&mut self, value: u64, bytes: usize) -> io::Result<()> {
            if self.measure_only {
                self.bit_pos += bytes * 8;
                self.unpadded_length += bytes * 8;
                return Ok(());
            }

            self.buffer.reserve(bytes);

            for i in 0..bytes {
                let byte = ((value >> (8 * (bytes - 1 - i))) & 0xFF) as u8;
                self.buffer.push(byte);
                trace!("Wrote byte {}: {}", i, byte);
            }

            self.bit_pos += bytes * 8;
            self.unpadded_length += bytes * 8;

            Ok(())
        }

        fn write_bits_optimized(&mut self, value: u64, bits: usize) -> io::Result<()> {
            if self.measure_only {
                self.bit_pos += bits;
                self.unpadded_length += bits;
                return Ok(());
            }

            let mut remaining_bits = bits;
            let mut val = value;

            while remaining_bits > 0 {
                let byte_pos = self.bit_pos / 8;
                let bit_offset = self.bit_pos % 8;
                let bits_available_in_byte = 8 - bit_offset;
                let bits_to_write = remaining_bits.min(bits_available_in_byte);

                while byte_pos >= self.buffer.len() {
                    self.buffer.push(0);
                }

                let shift = remaining_bits.saturating_sub(bits_to_write);
                let bits_to_write_val = if shift < 64 {
                    (val >> shift) & ((1u64 << bits_to_write) - 1)
                } else {
                    0
                };

                let byte_shift = bits_available_in_byte - bits_to_write;
                self.buffer[byte_pos] |= (bits_to_write_val as u8) << byte_shift;

                trace!(
                    "Wrote {} bits (value {}) to byte {} at offset {}",
                    bits_to_write,
                    bits_to_write_val,
                    byte_pos,
                    bit_offset
                );

                self.bit_pos += bits_to_write;
                remaining_bits -= bits_to_write;

                val &= if remaining_bits > 0 && remaining_bits < 64 {
                    (1u64 << remaining_bits) - 1
                } else if remaining_bits == 0 {
                    0
                } else {
                    u64::MAX
                };
            }

            self.unpadded_length += bits;
            Ok(())
        }

        fn read_bytes_fast(&mut self, bytes: usize) -> io::Result<u64> {
            let start_byte = self.read_pos / 8;
            let end_byte = start_byte + bytes;

            if end_byte > self.buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Not enough bytes to read",
                ));
            }

            let mut value = 0u64;
            for i in 0..bytes {
                let byte = self.buffer[start_byte + i];
                value |= (byte as u64) << (8 * (bytes - 1 - i));
                trace!("Read byte {}: {}", i, byte);
            }

            self.read_pos += bytes * 8;
            Ok(value)
        }

        fn read_bits_optimized(&mut self, bits: usize) -> io::Result<u64> {
            let mut remaining_bits = bits;
            let mut value = 0u64;

            while remaining_bits > 0 {
                let byte_pos = self.read_pos / 8;
                let bit_offset = self.read_pos % 8;
                let bits_available_in_byte = 8 - bit_offset;
                let bits_to_read = remaining_bits.min(bits_available_in_byte);

                if byte_pos >= self.buffer.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Buffer underflow during optimized read",
                    ));
                }

                let byte_shift = bits_available_in_byte - bits_to_read;
                let mask = if bits_to_read >= 8 {
                    0xFF
                } else {
                    (1u8 << bits_to_read) - 1
                };
                let bits_value = (self.buffer[byte_pos] >> byte_shift) & mask;

                let result_shift = remaining_bits - bits_to_read;
                if result_shift < 64 {
                    value |= (bits_value as u64) << result_shift;
                }

                self.read_pos += bits_to_read;
                remaining_bits -= bits_to_read;
            }

            Ok(value)
        }
    }

    impl BitWrite for BitBuffer {
        fn write_bit(&mut self, bit: bool) -> io::Result<()> {
            if self.measure_only {
                self.bit_pos += 1;
                self.unpadded_length += 1;
                return Ok(());
            }

            let byte_pos = self.bit_pos / 8;
            let bit_offset = self.bit_pos % 8;

            if byte_pos >= self.buffer.len() {
                self.buffer.push(0);
            }

            if bit {
                self.buffer[byte_pos] |= 1 << (7 - bit_offset);
            } else {
                self.buffer[byte_pos] &= !(1 << (7 - bit_offset));
            }

            self.bit_pos += 1;
            self.unpadded_length += 1;
            Ok(())
        }

        fn write_bits(&mut self, value: u64, bits: usize) -> io::Result<()> {
            if bits > 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Bits exceed 64",
                ));
            }
            if bits == 0 {
                return Ok(());
            }

            let val = if bits >= 64 {
                value
            } else {
                value & ((1u64 << bits) - 1)
            };

            if self.bit_pos.is_multiple_of(8) && bits.is_multiple_of(8) {
                return self.write_bytes_fast(val, bits / 8);
            }

            self.write_bits_optimized(val, bits)
        }

        fn bit_pos(&self) -> usize {
            self.bit_pos
        }
    }

    impl BitRead for BitBuffer {
        fn read_bit(&mut self) -> io::Result<bool> {
            let byte_pos = self.read_pos / 8;
            let bit_offset = self.read_pos % 8;

            if byte_pos >= self.buffer.len() {
                debug!("Error: Buffer underflow at read_pos: {}", self.read_pos);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Buffer underflow",
                ));
            }

            let bit = (self.buffer[byte_pos] & (1 << (7 - bit_offset))) != 0;
            self.read_pos += 1;
            Ok(bit)
        }

        fn read_bits(&mut self, bits: usize) -> io::Result<u64> {
            if bits > 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Bits exceed 64",
                ));
            }
            if bits == 0 {
                return Ok(0);
            }

            if self.read_pos.is_multiple_of(8) && bits.is_multiple_of(8) {
                return self.read_bytes_fast(bits / 8);
            }

            self.read_bits_optimized(bits)
        }

        #[allow(clippy::misnamed_getters)]
        fn bit_pos(&self) -> usize {
            self.read_pos
        }
    }
}

pub trait BitSerialize {
    fn bit_serialize<W: bit_io::BitWrite>(&self, writer: &mut W) -> std::io::Result<()>;
}

pub trait BitDeserialize: Sized {
    fn bit_deserialize<R: bit_io::BitRead>(reader: &mut R) -> std::io::Result<Self>;
}

pub trait ByteAlignedSerialize {
    fn byte_aligned_serialize<W: Write + WriteBytesExt>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()>;
}

pub trait ByteAlignedDeserialize: Sized {
    fn byte_aligned_deserialize<R: Read + ReadBytesExt>(reader: &mut R) -> std::io::Result<Self>;
}

/// Trait for delta-compressed network types.
/// Generated by `#[derive(NetworkDelta)]`.
pub trait NetworkDelta {
    /// The delta type containing only changed fields.
    type Delta: BitSerialize + BitDeserialize;

    /// Compute a delta from a baseline to the current state.
    fn diff(&self, baseline: &Self) -> Self::Delta;

    /// Apply a delta to this state, updating changed fields.
    fn apply(&mut self, delta: &Self::Delta);
}
