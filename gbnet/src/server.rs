//! Server-side networking API.
//!
//! [`NetServer`] manages multiple client connections, handles the connection
//! handshake, and dispatches incoming messages as [`ServerEvent`]s.
use rand::random;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::{
    congestion,
    connection::{Connection, ConnectionState, DisconnectReason},
    packet::{deny_reason, disconnect_reason, Packet, PacketHeader, PacketType},
    security::{self, ConnectionRateLimiter},
    socket::{SocketError, UdpSocket},
    wire, NetworkConfig, NetworkStats,
};

/// Events emitted by [`NetServer::update`].
#[derive(Debug)]
pub enum ServerEvent {
    ClientConnected(SocketAddr),
    ClientDisconnected(SocketAddr, DisconnectReason),
    Message {
        addr: SocketAddr,
        channel: u8,
        data: Vec<u8>,
    },
    ClientMigrated {
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    },
}

struct PendingConnection {
    server_salt: u64,
    created_at: Instant,
}

/// A game server that listens for client connections over UDP.
///
/// Call [`NetServer::update`] once per game tick to process packets,
/// send keepalives, and collect events.
/// Minimum interval between migrations for the same connection.
const MIGRATION_COOLDOWN: Duration = Duration::from_secs(5);

pub struct NetServer {
    socket: UdpSocket,
    connections: HashMap<SocketAddr, Connection>,
    pending: HashMap<SocketAddr, PendingConnection>,
    disconnecting: HashMap<SocketAddr, Connection>,
    config: NetworkConfig,
    rate_limiter: ConnectionRateLimiter,
    cookie_secret: [u8; 32],
    /// Tracks last migration time per migration_token to rate-limit migrations.
    migration_cooldowns: HashMap<u64, Instant>,
}

impl NetServer {
    /// Bind a server to the given address with the specified configuration.
    pub fn bind(addr: SocketAddr, config: NetworkConfig) -> Result<Self, SocketError> {
        if let Err(e) = config.validate() {
            return Err(SocketError::Other(e.to_string()));
        }
        let socket = UdpSocket::bind(addr)?;
        let rate_limit = config.rate_limit_per_second;
        let mut cookie_secret = [0u8; 32];
        for (i, byte) in cookie_secret.iter_mut().enumerate() {
            *byte = random::<u8>().wrapping_add(i as u8);
        }
        Ok(Self {
            socket,
            connections: HashMap::new(),
            pending: HashMap::new(),
            disconnecting: HashMap::new(),
            config: config.clone(),
            rate_limiter: ConnectionRateLimiter::new(rate_limit),
            cookie_secret,
            migration_cooldowns: HashMap::new(),
        })
    }

    /// Process incoming packets, send keepalives, and return events.
    /// Call this once per game tick.
    pub fn update(&mut self) -> Vec<ServerEvent> {
        let mut events = Vec::new();

        let mut incoming: Vec<(SocketAddr, Packet)> = Vec::new();
        loop {
            match self.socket.recv_from() {
                Ok((data, addr)) => {
                    let validated = match security::validate_and_strip_crc32(data) {
                        Some(valid) => valid.to_vec(),
                        None => continue,
                    };
                    let packet = match Packet::deserialize(&validated) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if packet.header.protocol_id != self.config.protocol_id {
                        continue;
                    }
                    if let Some(conn) = self.connections.get_mut(&addr) {
                        conn.record_bytes_received(validated.len());
                    }
                    incoming.push((addr, packet));
                }
                Err(SocketError::WouldBlock) => break,
                Err(_) => break,
            }
        }

        for (addr, packet) in incoming {
            self.handle_server_packet(addr, packet, &mut events);
        }

        let mut disconnected = Vec::new();
        let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
        for addr in addrs {
            let conn = self.connections.get_mut(&addr).unwrap();

            if let Err(_e) = conn.update_tick() {
                disconnected.push((addr, DisconnectReason::Timeout));
                continue;
            }

            let packets = conn.drain_send_queue();
            for packet in packets {
                if let Ok(data) = packet.serialize() {
                    let mut data_with_crc = data;
                    security::append_crc32(&mut data_with_crc);
                    let byte_len = data_with_crc.len();
                    if let Err(e) = self.socket.send_to(&data_with_crc, addr) {
                        log::warn!("Failed to send to {}: {:?}", addr, e);
                        let conn = self.connections.get_mut(&addr).unwrap();
                        conn.stats.send_errors += 1;
                    } else {
                        let conn = self.connections.get_mut(&addr).unwrap();
                        conn.record_bytes_sent(byte_len);
                    }
                }
            }

            let conn = self.connections.get_mut(&addr).unwrap();
            let max_channels = conn.channel_count();
            for ch in 0..max_channels as u8 {
                while let Some(data) = conn.receive(ch) {
                    events.push(ServerEvent::Message {
                        addr,
                        channel: ch,
                        data,
                    });
                }
            }
        }

        for (addr, reason) in disconnected {
            self.connections.remove(&addr);
            events.push(ServerEvent::ClientDisconnected(addr, reason));
        }

        let mut finished_disconnecting = Vec::new();
        for (addr, conn) in &mut self.disconnecting {
            let _ = conn.update(&mut self.socket);
            if conn.state() == ConnectionState::Disconnected {
                finished_disconnecting.push(*addr);
            }
        }
        for addr in finished_disconnecting {
            self.disconnecting.remove(&addr);
        }

        let timeout = self.config.connection_request_timeout;
        self.pending.retain(|_, p| p.created_at.elapsed() < timeout);
        self.rate_limiter.cleanup();
        self.migration_cooldowns
            .retain(|_, last| last.elapsed() < MIGRATION_COOLDOWN);

        events
    }

    /// Send a reliable message to a connected client on the given channel.
    pub fn send(
        &mut self,
        addr: SocketAddr,
        channel: u8,
        data: &[u8],
    ) -> Result<(), crate::connection::ConnectionError> {
        self.send_with_reliability(addr, channel, data, true)
    }

    pub fn send_with_reliability(
        &mut self,
        addr: SocketAddr,
        channel: u8,
        data: &[u8],
        reliable: bool,
    ) -> Result<(), crate::connection::ConnectionError> {
        if let Some(conn) = self.connections.get_mut(&addr) {
            conn.send(channel, data, reliable)
        } else {
            Err(crate::connection::ConnectionError::NotConnected)
        }
    }

    /// Broadcast a message to all connected clients, optionally excluding one.
    pub fn broadcast(&mut self, channel: u8, data: &[u8], except: Option<SocketAddr>) {
        let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
        for addr in addrs {
            if except == Some(addr) {
                continue;
            }
            let _ = self.send(addr, channel, data);
        }
    }

    /// Disconnect a client with the given reason code.
    pub fn disconnect(&mut self, addr: SocketAddr, reason: u8) {
        if let Some(mut conn) = self.connections.remove(&addr) {
            let _ = conn.disconnect(reason);
            let _ = conn.update(&mut self.socket);
            self.disconnecting.insert(addr, conn);
        }
    }

    /// Shut down the server, disconnecting all clients gracefully.
    pub fn shutdown(&mut self) {
        let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
        for addr in addrs {
            self.disconnect(addr, disconnect_reason::REQUESTED);
        }
    }

    pub fn connections(&self) -> impl Iterator<Item = (&SocketAddr, &Connection)> {
        self.connections.iter()
    }

    pub fn stats(&self, addr: SocketAddr) -> Option<&NetworkStats> {
        self.connections.get(&addr).map(|c| c.stats())
    }

    pub fn client_count(&self) -> usize {
        self.connections.len()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, SocketError> {
        self.socket.local_addr()
    }

    /// Attempt to migrate an existing connection to a new address.
    /// Returns the old address if migration succeeded.
    fn try_migrate(&mut self, new_addr: SocketAddr, header: &PacketHeader) -> Option<SocketAddr> {
        if !self.config.enable_connection_migration {
            return None;
        }

        let now = Instant::now();

        // Find a connection whose sequence range matches the incoming packet
        let old_addr = self.connections.iter().find_map(|(addr, conn)| {
            if conn.state() != ConnectionState::Connected {
                return None;
            }
            // Check sequence is plausible (within reasonable window)
            let seq_diff = crate::util::sequence_diff(header.sequence, conn.remote_sequence).abs();
            if seq_diff > conn.config().max_sequence_distance as i32 {
                return None;
            }
            // Check migration cooldown
            let token = conn.migration_token();
            if let Some(last) = self.migration_cooldowns.get(&token) {
                if now.duration_since(*last) < MIGRATION_COOLDOWN {
                    return None;
                }
            }
            Some(*addr)
        })?;

        // Perform migration
        let mut conn = self.connections.remove(&old_addr)?;
        let token = conn.migration_token();
        conn.set_remote_addr(new_addr);
        self.migration_cooldowns.insert(token, now);
        self.connections.insert(new_addr, conn);

        Some(old_addr)
    }

    fn handle_server_packet(
        &mut self,
        addr: SocketAddr,
        packet: Packet,
        events: &mut Vec<ServerEvent>,
    ) {
        match packet.packet_type {
            PacketType::ConnectionRequest => {
                if !self.rate_limiter.allow(addr) {
                    return;
                }

                if self.connections.contains_key(&addr) {
                    self.send_raw(addr, PacketType::ConnectionAccept);
                    return;
                }

                if self.config.enable_stateless_cookie {
                    // Respond with a cookie instead of allocating state immediately
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        / crate::config::DEFAULT_COOKIE_WINDOW_SECS;
                    let cookie = security::generate_cookie(&addr, timestamp, &self.cookie_secret);
                    let (high, low) = security::cookie_to_u64_pair(&cookie);
                    self.send_raw(
                        addr,
                        PacketType::ConnectionCookie {
                            cookie_high: high,
                            cookie_low: low,
                        },
                    );
                    return;
                }

                if let Some(pending) = self.pending.get(&addr) {
                    self.send_raw(
                        addr,
                        PacketType::ConnectionChallenge {
                            server_salt: pending.server_salt,
                        },
                    );
                    return;
                }

                if self.pending.len() >= self.config.max_pending {
                    return;
                }
                if self.connections.len() >= self.config.max_clients {
                    self.send_raw(
                        addr,
                        PacketType::ConnectionDeny {
                            reason: deny_reason::SERVER_FULL,
                        },
                    );
                    return;
                }

                let server_salt: u64 = random();
                self.send_raw(addr, PacketType::ConnectionChallenge { server_salt });
                self.pending.insert(
                    addr,
                    PendingConnection {
                        server_salt,
                        created_at: Instant::now(),
                    },
                );
            }
            PacketType::ConnectionRequestWithCookie {
                cookie_high,
                cookie_low,
            } => {
                if !self.rate_limiter.allow(addr) {
                    return;
                }

                if self.connections.contains_key(&addr) {
                    self.send_raw(addr, PacketType::ConnectionAccept);
                    return;
                }

                // Validate the cookie
                let cookie = security::cookie_from_u64_pair(cookie_high, cookie_low);
                let current_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if !security::validate_cookie(
                    &cookie,
                    &addr,
                    current_timestamp,
                    &self.cookie_secret,
                    crate::config::DEFAULT_COOKIE_WINDOW_SECS,
                ) {
                    return;
                }

                // Cookie valid — proceed to salt challenge
                if let Some(pending) = self.pending.get(&addr) {
                    self.send_raw(
                        addr,
                        PacketType::ConnectionChallenge {
                            server_salt: pending.server_salt,
                        },
                    );
                    return;
                }

                if self.pending.len() >= self.config.max_pending {
                    return;
                }
                if self.connections.len() >= self.config.max_clients {
                    self.send_raw(
                        addr,
                        PacketType::ConnectionDeny {
                            reason: deny_reason::SERVER_FULL,
                        },
                    );
                    return;
                }

                let server_salt: u64 = random();
                self.send_raw(addr, PacketType::ConnectionChallenge { server_salt });
                self.pending.insert(
                    addr,
                    PendingConnection {
                        server_salt,
                        created_at: Instant::now(),
                    },
                );
            }
            PacketType::ConnectionResponse { client_salt } => {
                if self.connections.contains_key(&addr) {
                    self.send_raw(addr, PacketType::ConnectionAccept);
                    return;
                }

                if let Some(pending) = self.pending.remove(&addr) {
                    if client_salt == 0 || client_salt == pending.server_salt {
                        self.send_raw(
                            addr,
                            PacketType::ConnectionDeny {
                                reason: crate::packet::deny_reason::INVALID_CHALLENGE,
                            },
                        );
                        return;
                    }
                    self.send_raw(addr, PacketType::ConnectionAccept);

                    let local_addr = self.socket.local_addr().unwrap_or(addr);
                    let mut conn = Connection::new(self.config.clone(), local_addr, addr);
                    conn.set_state(ConnectionState::Connected);
                    conn.touch_recv_time();
                    self.connections.insert(addr, conn);
                    events.push(ServerEvent::ClientConnected(addr));
                }
            }
            PacketType::Disconnect { reason } => {
                if self.connections.remove(&addr).is_some() {
                    self.send_raw(
                        addr,
                        PacketType::Disconnect {
                            reason: disconnect_reason::REQUESTED,
                        },
                    );
                    events.push(ServerEvent::ClientDisconnected(
                        addr,
                        DisconnectReason::from(reason),
                    ));
                }
            }
            PacketType::Payload {
                channel,
                is_fragment,
            } => {
                let effective_addr = if self.connections.contains_key(&addr) {
                    addr
                } else if let Some(old_addr) = self.try_migrate(addr, &packet.header) {
                    events.push(ServerEvent::ClientMigrated {
                        old_addr,
                        new_addr: addr,
                    });
                    addr
                } else {
                    return;
                };
                let conn = self.connections.get_mut(&effective_addr).unwrap();
                if packet.payload.len() > conn.config().default_channel_config.max_message_size {
                    return;
                }
                conn.touch_recv_time();
                conn.process_incoming_header(&packet.header);
                if is_fragment {
                    if let Some(assembled) =
                        conn.fragment_assembler.process_fragment(&packet.payload)
                    {
                        conn.receive_payload_direct(channel, assembled);
                    }
                } else {
                    conn.receive_payload_direct(channel, packet.payload);
                }
            }
            PacketType::BatchedPayload { channel } => {
                if let Some(conn) = self.connections.get_mut(&addr) {
                    conn.touch_recv_time();
                    conn.process_incoming_header(&packet.header);
                    if let Some(messages) = congestion::unbatch_messages(&packet.payload) {
                        for msg in messages {
                            conn.receive_payload_direct(channel, msg);
                        }
                    }
                }
            }
            PacketType::MtuProbe { probe_size } => {
                if let Some(conn) = self.connections.get_mut(&addr) {
                    conn.touch_recv_time();
                    conn.process_incoming_header(&packet.header);
                    self.send_raw(addr, PacketType::MtuProbeAck { probe_size });
                }
            }
            PacketType::MtuProbeAck { probe_size } => {
                if let Some(conn) = self.connections.get_mut(&addr) {
                    conn.touch_recv_time();
                    conn.process_incoming_header(&packet.header);
                    conn.mtu_discovery.on_probe_success(probe_size as usize);
                }
            }
            PacketType::KeepAlive | PacketType::AckOnly => {
                if let Some(conn) = self.connections.get_mut(&addr) {
                    conn.touch_recv_time();
                    conn.process_incoming_header(&packet.header);
                }
            }
            _ => {}
        }
    }

    fn send_raw(&mut self, addr: SocketAddr, packet_type: PacketType) {
        wire::send_raw_packet(
            &mut self.socket,
            addr,
            self.config.protocol_id,
            0,
            packet_type,
        );
    }
}

impl Drop for NetServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}
