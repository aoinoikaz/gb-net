//! Client-side networking API.
//!
//! [`NetClient`] connects to a server and provides send/receive through
//! channels with configurable delivery modes.
use std::net::SocketAddr;
use std::time::Instant;

use crate::{
    congestion,
    connection::{Connection, ConnectionError, ConnectionState, DisconnectReason},
    packet::{disconnect_reason, Packet, PacketType},
    security,
    socket::{SocketError, UdpSocket},
    wire, NetworkConfig, NetworkStats,
};

/// Events emitted by [`NetClient::update`].
#[derive(Debug)]
pub enum ClientEvent {
    Connected,
    Disconnected(DisconnectReason),
    Message { channel: u8, data: Vec<u8> },
}

/// A game client that connects to a server over UDP.
///
/// Call [`NetClient::update`] once per game tick to process packets and collect events.
pub struct NetClient {
    socket: UdpSocket,
    connection: Connection,
    server_addr: SocketAddr,
    connected_notified: bool,
    state: ClientState,
    connect_time: Instant,
    disconnect_time: Option<Instant>,
    disconnect_retry_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientState {
    Connecting,
    ChallengeResponse,
    Connected,
    Disconnecting,
    Disconnected,
}

impl NetClient {
    /// Connect to a server at the given address. Initiates the handshake immediately.
    pub fn connect(server_addr: SocketAddr, config: NetworkConfig) -> Result<Self, SocketError> {
        if let Err(e) = config.validate() {
            return Err(SocketError::Other(e.to_string()));
        }
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = UdpSocket::bind(bind_addr)?;
        let local_addr = socket.local_addr()?;

        let connection = Connection::new(config, local_addr, server_addr);

        let mut client = Self {
            socket,
            connection,
            server_addr,
            connected_notified: false,
            state: ClientState::Connecting,
            connect_time: Instant::now(),
            disconnect_time: None,
            disconnect_retry_count: 0,
        };

        client.send_raw(PacketType::ConnectionRequest);
        Ok(client)
    }

    /// Process incoming packets, send keepalives, and return events.
    /// Call this once per game tick.
    pub fn update(&mut self) -> Vec<ClientEvent> {
        let mut events = Vec::new();

        if matches!(
            self.state,
            ClientState::Connecting | ClientState::ChallengeResponse
        ) {
            let config = self.connection.config().clone();
            if self.connect_time.elapsed() > config.connection_timeout {
                self.state = ClientState::Disconnected;
                events.push(ClientEvent::Disconnected(DisconnectReason::Timeout));
                return events;
            }
        }

        if self.state == ClientState::Disconnecting {
            let config = self.connection.config().clone();
            if let Some(disc_time) = self.disconnect_time {
                if disc_time.elapsed() > config.disconnect_retry_timeout {
                    if self.disconnect_retry_count >= config.disconnect_retries {
                        self.state = ClientState::Disconnected;
                        events.push(ClientEvent::Disconnected(DisconnectReason::Requested));
                        return events;
                    }
                    self.disconnect_retry_count += 1;
                    self.disconnect_time = Some(Instant::now());
                    self.send_raw(PacketType::Disconnect {
                        reason: disconnect_reason::REQUESTED,
                    });
                }
            }
        }

        loop {
            match self.socket.recv_from() {
                Ok((data, addr)) => {
                    if addr != self.server_addr {
                        continue;
                    }
                    let validated = match security::validate_and_strip_crc32(data) {
                        Some(valid) => valid.to_vec(),
                        None => continue,
                    };
                    let packet = match Packet::deserialize(&validated) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if packet.header.protocol_id != self.connection.config().protocol_id {
                        continue;
                    }
                    self.connection.record_bytes_received(validated.len());
                    self.handle_packet(packet, &mut events);
                }
                Err(SocketError::WouldBlock) => break,
                Err(_) => break,
            }
        }

        if self.state == ClientState::Connected {
            if let Err(_e) = self.connection.update_tick() {
                self.state = ClientState::Disconnected;
                events.push(ClientEvent::Disconnected(DisconnectReason::Timeout));
                return events;
            }

            let packets = self.connection.drain_send_queue();
            for packet in packets {
                if let Ok(data) = packet.serialize() {
                    let mut data_with_crc = data;
                    security::append_crc32(&mut data_with_crc);
                    let byte_len = data_with_crc.len();
                    if let Err(e) = self.socket.send_to(&data_with_crc, self.server_addr) {
                        log::warn!("Failed to send to {}: {:?}", self.server_addr, e);
                        self.connection.stats.send_errors += 1;
                    } else {
                        self.connection.record_bytes_sent(byte_len);
                    }
                }
            }

            let channel_count = self.connection.channel_count();
            for ch in 0..channel_count as u8 {
                while let Some(data) = self.connection.receive(ch) {
                    events.push(ClientEvent::Message { channel: ch, data });
                }
            }
        }

        events
    }

    /// Send a reliable message to the server on the given channel.
    pub fn send(&mut self, channel: u8, data: &[u8]) -> Result<(), ConnectionError> {
        self.send_with_reliability(channel, data, true)
    }

    pub fn send_with_reliability(
        &mut self,
        channel: u8,
        data: &[u8],
        reliable: bool,
    ) -> Result<(), ConnectionError> {
        if self.state != ClientState::Connected {
            return Err(ConnectionError::NotConnected);
        }
        self.connection.send(channel, data, reliable)?;
        Ok(())
    }

    /// Reconnect to the server, resetting all connection state and initiating a new handshake.
    pub fn reconnect(&mut self) {
        self.connection.reset_connection();
        self.connection.set_state(ConnectionState::Disconnected);
        self.connection.stats = NetworkStats::default();
        self.connected_notified = false;
        self.state = ClientState::Connecting;
        self.connect_time = Instant::now();
        self.disconnect_time = None;
        self.disconnect_retry_count = 0;
        self.send_raw(PacketType::ConnectionRequest);
    }

    /// Disconnect from the server. Sends a disconnect packet and enters
    /// `Disconnecting` state with retry logic until acknowledged or max retries.
    pub fn disconnect(&mut self) {
        self.send_raw(PacketType::Disconnect {
            reason: disconnect_reason::REQUESTED,
        });
        self.state = ClientState::Disconnecting;
        self.disconnect_time = Some(Instant::now());
        self.disconnect_retry_count = 0;
    }

    /// Shut down the client, sending a disconnect to the server.
    pub fn shutdown(&mut self) {
        if self.state == ClientState::Connected || self.state == ClientState::Disconnecting {
            self.send_raw(PacketType::Disconnect {
                reason: disconnect_reason::REQUESTED,
            });
            self.state = ClientState::Disconnected;
        }
    }

    pub fn state(&self) -> ConnectionState {
        match self.state {
            ClientState::Connecting => ConnectionState::Connecting,
            ClientState::ChallengeResponse => ConnectionState::ChallengeResponse,
            ClientState::Connected => ConnectionState::Connected,
            ClientState::Disconnecting => ConnectionState::Disconnecting,
            ClientState::Disconnected => ConnectionState::Disconnected,
        }
    }

    pub fn stats(&self) -> &NetworkStats {
        self.connection.stats()
    }

    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected
    }

    pub fn channel_stats(&self) -> Vec<crate::stats::ChannelStats> {
        self.connection.channel_stats()
    }

    fn handle_packet(&mut self, packet: Packet, events: &mut Vec<ClientEvent>) {
        match (&self.state, packet.packet_type) {
            (
                ClientState::Connecting,
                PacketType::ConnectionCookie {
                    cookie_high,
                    cookie_low,
                },
            ) => {
                // Echo the cookie back in a ConnectionRequestWithCookie
                self.send_raw(PacketType::ConnectionRequestWithCookie {
                    cookie_high,
                    cookie_low,
                });
            }
            (ClientState::Connecting, PacketType::ConnectionChallenge { server_salt }) => {
                self.connection.set_server_salt(server_salt);
                self.state = ClientState::ChallengeResponse;
                self.send_raw(PacketType::ConnectionResponse {
                    client_salt: self.connection.client_salt(),
                });
            }
            (ClientState::ChallengeResponse, PacketType::ConnectionChallenge { .. }) => {
                self.send_raw(PacketType::ConnectionResponse {
                    client_salt: self.connection.client_salt(),
                });
            }
            (ClientState::ChallengeResponse, PacketType::ConnectionAccept) => {
                self.state = ClientState::Connected;
                self.connection.set_state(ConnectionState::Connected);
                self.connection.touch_recv_time();
                if !self.connected_notified {
                    self.connected_notified = true;
                    events.push(ClientEvent::Connected);
                }
            }
            (
                ClientState::Connecting | ClientState::ChallengeResponse,
                PacketType::ConnectionDeny { reason },
            ) => {
                self.state = ClientState::Disconnected;
                events.push(ClientEvent::Disconnected(DisconnectReason::Unknown(reason)));
            }
            (ClientState::Connected, PacketType::Disconnect { reason }) => {
                self.state = ClientState::Disconnected;
                events.push(ClientEvent::Disconnected(DisconnectReason::from(reason)));
            }
            (
                ClientState::Connected,
                PacketType::Payload {
                    channel,
                    is_fragment,
                },
            ) => {
                if packet.payload.len()
                    > self
                        .connection
                        .config()
                        .default_channel_config
                        .max_message_size
                {
                    return;
                }
                self.connection.touch_recv_time();
                self.connection.process_incoming_header(&packet.header);
                if is_fragment {
                    if let Some(assembled) = self
                        .connection
                        .fragment_assembler
                        .process_fragment(&packet.payload)
                    {
                        self.connection.receive_payload_direct(channel, assembled);
                    }
                } else {
                    self.connection
                        .receive_payload_direct(channel, packet.payload);
                }
            }
            (ClientState::Connected, PacketType::MtuProbe { probe_size }) => {
                self.connection.touch_recv_time();
                self.connection.process_incoming_header(&packet.header);
                self.send_raw(PacketType::MtuProbeAck { probe_size });
            }
            (ClientState::Connected, PacketType::MtuProbeAck { probe_size }) => {
                self.connection.touch_recv_time();
                self.connection.process_incoming_header(&packet.header);
                self.connection
                    .mtu_discovery
                    .on_probe_success(probe_size as usize);
            }
            (ClientState::Connected, PacketType::BatchedPayload { channel }) => {
                self.connection.touch_recv_time();
                self.connection.process_incoming_header(&packet.header);
                if let Some(messages) = congestion::unbatch_messages(&packet.payload) {
                    for msg in messages {
                        self.connection.receive_payload_direct(channel, msg);
                    }
                }
            }
            (ClientState::Connected, PacketType::KeepAlive)
            | (ClientState::Connected, PacketType::AckOnly) => {
                self.connection.touch_recv_time();
                self.connection.process_incoming_header(&packet.header);
            }
            (ClientState::Disconnecting, PacketType::Disconnect { reason }) => {
                self.state = ClientState::Disconnected;
                events.push(ClientEvent::Disconnected(DisconnectReason::from(reason)));
            }
            _ => {}
        }
    }

    fn send_raw(&mut self, packet_type: PacketType) {
        wire::send_raw_packet(
            &mut self.socket,
            self.server_addr,
            self.connection.config().protocol_id,
            0,
            packet_type,
        );
    }
}

impl Drop for NetClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}
