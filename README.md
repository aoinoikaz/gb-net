<div align="center">
<h1>GB-Net</h1>
<p><strong>High-Performance Game Networking for Rust</strong></p>
<p>Bitpacked serialization. Reliable UDP transport. Built for real-time.</p>
<p><a href="#quick-start">Quick Start</a> · <a href="#delivery-modes">Delivery Modes</a> · <a href="#serialization-attributes">Serialization</a> · <a href="#architecture">Architecture</a></p>
<p>

[![CI](https://github.com/aoinoikaz/gbnet/actions/workflows/ci.yml/badge.svg)](https://github.com/aoinoikaz/gbnet/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-stable-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

</p>
</div>

---

## What is GB-Net?

GB-Net is a transport-level game networking library for Rust — think ENet, LiteNetLib, or yojimbo. It provides reliable UDP with bitpacked serialization, designed for synchronous polling game loops.

```
Game Code                    GB-Net                      Wire
─────────                    ──────                      ────
┌──────────┐   serialize   ┌──────────┐    UDP + CRC   ┌──────────┐
│ Structs  │──────────────▶│ Channels │───────────────▶│ Packets  │
│ Enums    │  bitpacked    │ Reliab.  │  fragment/mtu  │ On Wire  │
│ Vecs     │◀──────────────│ Congest. │◀───────────────│          │
└──────────┘  deserialize  └──────────┘   reassemble   └──────────┘
```

---

## Quick Start

```toml
[dependencies]
gbnet = { git = "https://github.com/aoinoikaz/gbnet.git" }
gbnet_macros = { git = "https://github.com/aoinoikaz/gbnet.git" }
```

### Server

```rust
use gbnet::{NetServer, NetworkConfig, ServerEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = NetworkConfig::default();
    let mut server = NetServer::bind("127.0.0.1:7777".parse()?, config)?;

    loop {
        for event in server.update() {
            match event {
                ServerEvent::ClientConnected(addr) => {
                    println!("Connected: {addr}");
                }
                ServerEvent::Message { addr, channel, data } => {
                    server.send(addr, channel, &data)?;
                }
                ServerEvent::ClientDisconnected(addr, reason) => {
                    println!("Disconnected: {addr} ({reason})");
                }
                ServerEvent::ClientMigrated { old_addr, new_addr } => {
                    println!("Migrated: {old_addr} -> {new_addr}");
                }
            }
        }
    }
}
```

### Client

```rust
use gbnet::{NetClient, NetworkConfig, ClientEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = NetworkConfig::default();
    let mut client = NetClient::connect("127.0.0.1:7777".parse()?, config)?;

    loop {
        for event in client.update() {
            match event {
                ClientEvent::Connected => {
                    client.send(0, b"Hello server!")?;
                }
                ClientEvent::Message { channel, data } => {
                    println!("ch{channel}: {} bytes", data.len());
                }
                ClientEvent::Disconnected(reason) => {
                    println!("Disconnected: {reason}");
                    return Ok(());
                }
            }
        }
    }
}
```

### Serialization

```rust
use gbnet::{NetworkSerialize, BitSerialize, BitDeserialize, BitBuffer};

#[derive(NetworkSerialize, Debug, PartialEq)]
struct PlayerUpdate {
    #[bits = 10]
    x: u16,          // 0-1023
    #[bits = 10]
    y: u16,          // 0-1023
    #[bits = 7]
    health: u8,      // 0-127
    moving: bool,    // 1 bit
}
// 28 bits on wire (3.5 bytes) instead of 5 bytes uncompressed

let update = PlayerUpdate { x: 512, y: 768, health: 100, moving: true };
let mut buf = BitBuffer::new();
update.bit_serialize(&mut buf)?;
```

### Configuration

```rust
use gbnet::{NetworkConfig, ChannelConfig, DeliveryMode};
use std::time::Duration;

let config = NetworkConfig::default()
    .with_protocol_id(0xDEADBEEF)
    .with_max_clients(32)
    .with_mtu(1200)
    .with_connection_timeout(Duration::from_secs(10))
    .with_keepalive_interval(Duration::from_secs(1))
    .with_send_rate(60.0)
    .with_max_in_flight(256)
    // Per-channel delivery modes
    .with_channel_config(0, ChannelConfig::reliable_ordered().with_priority(0))
    .with_channel_config(1, ChannelConfig::unreliable().with_priority(128))
    .with_channel_config(2, ChannelConfig::reliable_sequenced().with_priority(64));
```

---

## Delivery Modes

| Mode | Reliable | Ordered | Use Case |
|---|---|---|---|
| `Unreliable` | No | No | Position updates, effects |
| `UnreliableSequenced` | No | Latest only | Rapidly changing state |
| `ReliableUnordered` | Yes | No | Inventory changes, stats |
| `ReliableOrdered` | Yes | In sequence | Chat, commands, events |
| `ReliableSequenced` | Yes | Latest only | Config updates |

Per-message reliability override is supported — send a reliable message on an unreliable channel (or vice versa) via `send_with_reliability()`.

---

## Features

| | |
|---|---|
| **Serialization** | Bitpacked encoding, derive macro, field-level `#[bits = N]` control, `#[with]` custom codecs, `#[skip_if]` conditional fields, byte-aligned mode |
| **Reliability** | Jacobson/Karels RTT, channel-owned retransmission with exponential backoff, fast retransmit (NACK-based), 64-bit ACK window, ACK-only packets, bounded in-flight tracking |
| **Fragmentation** | Auto split/reassembly, per-fragment retransmission, 32-bit fragment IDs, per-message timeout, memory-bounded buffers |
| **MTU Discovery** | Binary search probing with automatic probe timeout detection |
| **Security** | CRC32C integrity, stateless cookie handshake (amplification mitigation), challenge-response, IP-based rate limiting, deserialization bounds checking, AES-256-GCM encryption with full-entropy nonce salt (optional) |
| **Congestion** | Binary good/bad mode, optional cwnd-based congestion window (SlowStart/Avoidance/Recovery), packet pacing, send rate limiting |
| **Delta Compression** | `#[derive(NetworkDelta)]` for bitmask-based delta encoding, baseline tracking, automatic fallback to full state |
| **Replication** | Priority accumulator for bandwidth-limited entity sends, interest management (radius + grid AoI) |
| **Interpolation** | Client-side snapshot buffer with configurable playback delay and linear interpolation |
| **Batching** | Pack multiple small messages into single UDP packets |
| **Simulation** | Configurable loss, latency, jitter, duplicates, reordering, bandwidth limits |
| **Diagnostics** | Per-connection RTT, packet loss %, bandwidth up/down, channel stats, message drop counters, connection quality |
| **Disconnect** | Reliable disconnect with configurable retry and backoff (client and server) |
| **Reconnection** | Client-side `reconnect()` with full state reset and new handshake |
| **Migration** | Connection migration across address changes with rate-limited cooldown |

---

## Serialization Attributes

### Container

| Attribute | Target | Description |
|---|---|---|
| `#[default_bits(u8 = 4, u16 = 10)]` | struct/enum | Default bit widths per type |
| `#[default_max_len = 100]` | struct/enum | Default max length for Vec/String |
| `#[bits = 4]` | enum | Bits for variant discriminant |

### Variant

| Attribute | Description |
|---|---|
| `#[variant_id = N]` | Pin enum variant to a specific discriminant value (stable wire format) |

### Field

| Attribute | Description |
|---|---|
| `#[bits = N]` | Use N bits for this field |
| `#[byte_align]` | Pad to byte boundary before this field |
| `#[no_serialize]` | Skip field (uses `Default` on deserialize) |
| `#[max_len = N]` | Max length for Vec/String |
| `#[with = "path"]` | Use custom serialize/deserialize functions at `path` |
| `#[skip_if = "expr"]` | Conditionally skip field with 1-bit presence flag |

---

## Delta Compression

Derive delta structs automatically for bandwidth-efficient state replication:

```rust
use gbnet::{NetworkSerialize, NetworkDelta, BitSerialize, BitDeserialize};

#[derive(NetworkSerialize, NetworkDelta, Clone, Debug, PartialEq)]
struct PlayerState {
    #[bits = 10]
    x: u16,
    #[bits = 10]
    y: u16,
    #[bits = 7]
    health: u8,
}

// Generates `PlayerStateDelta` with Option<T> per field + bitmask serialization
let baseline = PlayerState { x: 100, y: 200, health: 80 };
let current = PlayerState { x: 105, y: 200, health: 80 };
let delta = current.diff(&baseline);  // Only x changed — 1-bit bitmask + 10-bit value

let mut updated = baseline.clone();
updated.apply(&delta);
assert_eq!(updated, current);
```

Use `DeltaTracker` and `BaselineManager` for wire-level delta transport with automatic baseline ACK tracking and fallback to full state.

---

## Snapshot Interpolation

Smooth client-side rendering with buffered interpolation:

```rust
use gbnet::{Interpolatable, SnapshotBuffer};

#[derive(Clone)]
struct Position { x: f32, y: f32 }

impl Interpolatable for Position {
    fn lerp(&self, other: &Self, t: f32) -> Self {
        Position {
            x: self.x + (other.x - self.x) * t,
            y: self.y + (other.y - self.y) * t,
        }
    }
}

let mut buffer = SnapshotBuffer::with_config(3, 100.0); // 100ms playback delay
buffer.push(0.0, Position { x: 0.0, y: 0.0 });
buffer.push(50.0, Position { x: 10.0, y: 5.0 });
buffer.push(100.0, Position { x: 20.0, y: 10.0 });

// Sample at render time (behind by playback delay)
if let Some(pos) = buffer.sample(150.0) {
    // Interpolated position at t=50ms
}
```

---

## Architecture

```
gbnet/
├── src/
│   ├── lib.rs              # Public API, re-exports, prelude
│   ├── config.rs           # NetworkConfig, ChannelConfig, DeliveryMode
│   ├── serialize/
│   │   ├── mod.rs          # BitBuffer, traits, bit_io
│   │   ├── primitives.rs   # Integers, floats, bool
│   │   └── collections.rs  # Vec, String, Array, Option, tuples
│   ├── packet.rs           # Packet header/type, wire format
│   ├── channel.rs          # 5 delivery modes, ACK tracking
│   ├── connection/
│   │   ├── mod.rs          # Connection state machine, migration
│   │   ├── handshake.rs    # Challenge-response handshake, dedup
│   │   └── io.rs           # Send/receive, queue management, cwnd pacing
│   ├── reliability.rs      # RTT estimation, fast retransmit, 64-bit ACK window
│   ├── security.rs         # CRC32C, stateless cookies, rate limiting, AES-GCM
│   ├── fragment.rs         # Fragmentation/reassembly, per-fragment retransmit, MTU discovery
│   ├── congestion.rs       # Binary + cwnd congestion control, pacing, batching
│   ├── delta.rs            # Delta compression transport, baseline tracking
│   ├── priority.rs         # Priority accumulator for entity replication
│   ├── interest.rs         # Area-of-interest filtering (radius, grid)
│   ├── interpolation.rs    # Snapshot interpolation buffer
│   ├── server.rs           # NetServer API, connection migration
│   ├── client.rs           # NetClient API (connect, reconnect, send)
│   ├── simulator.rs        # Network condition simulator
│   ├── wire.rs             # Shared packet utilities
│   ├── stats.rs            # Statistics types
│   └── util.rs             # Sequence number utilities
├── benches/
│   └── throughput.rs       # Criterion benchmarks
├── fuzz/
│   └── fuzz_targets/       # cargo-fuzz targets
└── tests/
    └── integration.rs      # End-to-end tests

gbnet_macros/
└── src/
    ├── lib.rs              # #[derive(NetworkSerialize)]
    └── delta.rs            # #[derive(NetworkDelta)]
```

---

## Examples

Run any example with `cargo run --example <name>`:

| Example | Description |
|---|---|
| `echo_server` | Minimal server that reflects all messages back |
| `echo_client` | Connects, sends a message, prints the echo reply, disconnects |
| `channels` | Demonstrates all 5 delivery modes side by side |
| `serialization` | Bitpacked serialize/deserialize round-trip with `#[bits = N]` |
| `configuration` | Custom config with multiple channel types and tuning |

---

## Build & Test

```bash
cargo test                          # Run all tests
cargo test --features encryption    # Include AES-GCM tests
cargo clippy -- -W clippy::all      # Lint
cargo fmt --check                   # Format check
cargo bench                         # Run benchmarks
```

### Fuzzing

Requires `cargo-fuzz` (`cargo install cargo-fuzz`):

```bash
cd gbnet
cargo fuzz run fuzz_packet_deserialize
cargo fuzz run fuzz_fragment_reassembly
cargo fuzz run fuzz_bitbuffer
```

---

## Contributing

Contributions welcome. Run `cargo test && cargo clippy -- -W clippy::all && cargo fmt --check` before submitting PRs.

---

<p align="center">
  <sub>MIT License · Built by <a href="https://github.com/aoinoikaz">Gondola Bros Entertainment</a></sub>
</p>
