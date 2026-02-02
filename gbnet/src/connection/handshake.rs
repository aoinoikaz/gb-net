use std::time::Instant;

use crate::packet::{disconnect_reason, Packet, PacketHeader, PacketType};

use super::{Connection, ConnectionError, ConnectionState};

impl Connection {
    pub fn connect(&mut self) -> Result<(), ConnectionError> {
        if self.state != ConnectionState::Disconnected {
            return Err(ConnectionError::AlreadyConnected);
        }

        self.state = ConnectionState::Connecting;
        self.connection_request_time = Some(Instant::now());
        self.connection_retry_count = 0;
        self.send_connection_request()?;
        Ok(())
    }

    pub fn disconnect(&mut self, reason: u8) -> Result<(), ConnectionError> {
        if self.state == ConnectionState::Disconnected {
            return Ok(());
        }

        let header = self.create_header();
        let packet = Packet::new(header, PacketType::Disconnect { reason });
        self.send_queue.push_back(packet);
        self.state = ConnectionState::Disconnecting;
        self.disconnect_time = Some(Instant::now());
        self.disconnect_retry_count = 0;
        Ok(())
    }

    pub(super) fn send_connection_request(&mut self) -> Result<(), ConnectionError> {
        let header = PacketHeader {
            protocol_id: self.config.protocol_id,
            sequence: 0,
            ack: 0,
            ack_bits: 0,
        };
        let packet = Packet::new(header, PacketType::ConnectionRequest);
        self.send_queue.push_back(packet);
        Ok(())
    }

    pub(super) fn handle_packet(&mut self, packet: Packet) -> Result<(), ConnectionError> {
        match (&self.state, &packet.packet_type) {
            (ConnectionState::Connecting, PacketType::ConnectionChallenge { server_salt }) => {
                self.server_salt = *server_salt;
                self.state = ConnectionState::ChallengeResponse;

                let header = self.create_header();
                let response = Packet::new(
                    header,
                    PacketType::ConnectionResponse {
                        client_salt: self.client_salt,
                    },
                );
                self.send_queue.push_back(response);
            }

            (ConnectionState::ChallengeResponse, PacketType::ConnectionAccept) => {
                self.state = ConnectionState::Connected;
                self.connection_start_time = Some(Instant::now());
                self.last_packet_recv_time = Instant::now();
                self.local_sequence = 0;
                self.remote_sequence = 0;
            }

            (
                ConnectionState::Connecting | ConnectionState::ChallengeResponse,
                PacketType::ConnectionDeny { reason },
            ) => {
                self.state = ConnectionState::Disconnected;
                return Err(ConnectionError::ConnectionDenied(*reason));
            }

            (ConnectionState::Connected, _) => {
                self.process_incoming_header(&packet.header);

                match packet.packet_type {
                    PacketType::Payload {
                        channel,
                        is_fragment: _,
                    } => {
                        if (channel as usize) < self.channels.len() {
                            self.channels[channel as usize].on_packet_received(packet.payload);
                        }
                    }
                    PacketType::BatchedPayload { channel } => {
                        if (channel as usize) < self.channels.len() {
                            if let Some(messages) =
                                crate::congestion::unbatch_messages(&packet.payload)
                            {
                                for msg in messages {
                                    self.channels[channel as usize].on_packet_received(msg);
                                }
                            }
                        }
                    }
                    PacketType::MtuProbe { probe_size } => {
                        let header = self.create_header();
                        let ack_packet =
                            Packet::new(header, PacketType::MtuProbeAck { probe_size });
                        self.send_queue.push_back(ack_packet);
                    }
                    PacketType::MtuProbeAck { probe_size } => {
                        self.mtu_discovery.on_probe_success(probe_size as usize);
                    }
                    PacketType::Disconnect { reason: _ } => {
                        let header = self.create_header();
                        let ack = Packet::new(
                            header,
                            PacketType::Disconnect {
                                reason: disconnect_reason::REQUESTED,
                            },
                        );
                        self.send_queue.push_back(ack);
                        self.state = ConnectionState::Disconnected;
                        self.reset_connection();
                    }
                    _ => {}
                }
            }

            (ConnectionState::Disconnecting, PacketType::Disconnect { .. }) => {
                self.state = ConnectionState::Disconnected;
                self.reset_connection();
            }

            _ => {}
        }
        Ok(())
    }

    pub(crate) fn reset_connection(&mut self) {
        self.connection_start_time = None;
        self.connection_request_time = None;
        self.local_sequence = 0;
        self.remote_sequence = 0;
        self.ack_bits = 0;
        self.send_queue.clear();
        self.recv_queue.clear();
        self.disconnect_time = None;
        self.disconnect_retry_count = 0;
        self.pending_ack_send = false;
        self.data_sent_this_tick = false;
        self.next_fragment_id = 0;
        self.pending_fragments.clear();

        for channel in &mut self.channels {
            channel.reset();
        }

        self.congestion = crate::congestion::CongestionController::new(
            self.config.send_rate,
            self.config.congestion_bad_loss_threshold,
            self.config.congestion_good_rtt_threshold,
            self.config.congestion_recovery_time,
        );
        self.bandwidth_up =
            crate::congestion::BandwidthTracker::new(std::time::Duration::from_secs(1));
        self.bandwidth_down =
            crate::congestion::BandwidthTracker::new(std::time::Duration::from_secs(1));
        self.fragment_assembler = crate::fragment::FragmentAssembler::new(
            self.config.fragment_timeout,
            self.config.max_reassembly_buffer_size,
        );
        self.mtu_discovery =
            crate::fragment::MtuDiscovery::new(crate::fragment::MIN_MTU, self.config.mtu);
    }
}
