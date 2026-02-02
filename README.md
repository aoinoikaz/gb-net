<div align="center">
<h1>GB-Net</h1>
<p><strong>High-Performance Game Networking for Rust</strong></p>
<p>Bitpacked serialization. Reliable UDP transport. Built for real-time.</p>
<p><a href="#quick-start">Quick Start</a> · <a href="#delivery-modes">Delivery Modes</a> · <a href="#serialization-attributes">Serialization</a> · <a href="#architecture">Architecture</a></p>
<p>

[![CI](https://github.com/gondola-bros-entertainment/GB-Net/actions/workflows/ci.yml/badge.svg)](https://github.com/gondola-bros-entertainment/GB-Net/actions/workflows/ci.yml)
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
gbnet = { git = "https://github.com/gondola-bros-entertainment/GB-Net.git" }
gbnet_macros = { git = "https://github.com/gondola-bros-entertainment/GB-Net.git" }
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
| **Serialization** | Bitpacked encoding, derive macro, field-level `#[bits = N]` control, byte-aligned mode |
| **Reliability** | Jacobson/Karels RTT, channel-owned retransmission with exponential backoff, bounded in-flight tracking |
| **Fragmentation** | Auto split/reassembly when payload exceeds threshold, per-message timeout, memory-bounded buffers |
| **MTU Discovery** | Binary search probing with automatic probe timeout detection |
| **Security** | CRC32C integrity, challenge-response handshake, IP-based rate limiting, deserialization bounds checking, AES-256-GCM encryption with per-connection nonce salt (optional) |
| **Congestion** | Binary good/bad mode, packet loss + RTT monitoring, send rate limiting |
| **Batching** | Pack multiple small messages into single UDP packets |
| **Simulation** | Configurable loss, latency, jitter, duplicates, reordering, bandwidth limits |
| **Diagnostics** | Per-connection RTT, packet loss %, bandwidth up/down, channel stats, connection quality |
| **Disconnect** | Reliable disconnect with configurable retry and backoff (client and server) |
| **Reconnection** | Client-side `reconnect()` with full state reset and new handshake |

---

## Serialization Attributes

### Container

| Attribute | Target | Description |
|---|---|---|
| `#[default_bits(u8 = 4, u16 = 10)]` | struct/enum | Default bit widths per type |
| `#[default_max_len = 100]` | struct/enum | Default max length for Vec/String |
| `#[bits = 4]` | enum | Bits for variant discriminant |

### Field

| Attribute | Description |
|---|---|
| `#[bits = N]` | Use N bits for this field |
| `#[byte_align]` | Pad to byte boundary before this field |
| `#[no_serialize]` | Skip field (uses `Default` on deserialize) |
| `#[max_len = N]` | Max length for Vec/String |

---

## Architecture

```
gbnet/
├── src/
│   ├── lib.rs              # Public API, re-exports
│   ├── config.rs           # NetworkConfig, ChannelConfig, DeliveryMode
│   ├── serialize/
│   │   ├── mod.rs          # BitBuffer, traits, bit_io
│   │   ├── primitives.rs   # Integers, floats, bool
│   │   └── collections.rs  # Vec, String, Array, Option, tuples
│   ├── packet.rs           # Packet header/type, wire format
│   ├── channel.rs          # 5 delivery modes, ACK tracking
│   ├── connection/
│   │   ├── mod.rs          # Connection state machine
│   │   ├── handshake.rs    # Challenge-response handshake, dedup
│   │   └── io.rs           # Send/receive, queue management
│   ├── reliability.rs      # RTT estimation, retransmit, loss tracking
│   ├── security.rs         # CRC32C, tokens, rate limiting, AES-GCM
│   ├── fragment.rs         # Fragmentation/reassembly, MTU discovery
│   ├── congestion.rs       # Congestion control, message batching
│   ├── server.rs           # NetServer API
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
    └── lib.rs              # #[derive(NetworkSerialize)]
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
  <sub>MIT License · Built by <a href="https://github.com/gondola-bros-entertainment">GondolaBros</a> · A <a href="https://novavero.ai">Novavero AI</a> project</sub>
</p>
