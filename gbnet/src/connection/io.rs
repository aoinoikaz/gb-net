use std::time::Instant;

use crate::{
    packet::{disconnect_reason, Packet, PacketType},
    security,
    socket::{SocketError, UdpSocket},
};

use super::{Connection, ConnectionError, ConnectionState};

impl Connection {
    /// Full update cycle including socket I/O. Used by Connection-driven flows
    /// (e.g. disconnecting connections that own their socket interaction).
    pub fn update(&mut self, socket: &mut UdpSocket) -> Result<(), ConnectionError> {
        self.update_tick()?;
        self.process_send_queue(socket)?;
        self.receive_packets(socket)?;
        Ok(())
    }

    /// Update connection state without socket I/O. Server/Client call this per tick
    /// after feeding received packets in, then drain `send_queue` themselves.
    pub fn update_tick(&mut self) -> Result<(), ConnectionError> {
        let now = Instant::now();

        if self.state != ConnectionState::Disconnected
            && self.state != ConnectionState::Disconnecting
        {
            let time_since_recv = now.duration_since(self.last_packet_recv_time);
            if time_since_recv > self.config.connection_timeout {
                self.state = ConnectionState::Disconnected;
                self.reset_connection();
                return Err(ConnectionError::Timeout);
            }
        }

        self.fragment_assembler.cleanup();

        match self.state {
            ConnectionState::Connecting => {
                if let Some(request_time) = self.connection_request_time {
                    if now.duration_since(request_time) > self.config.connection_request_timeout {
                        self.connection_retry_count += 1;
                        if self.connection_retry_count > self.config.connection_request_max_retries
                        {
                            self.state = ConnectionState::Disconnected;
                            return Err(ConnectionError::Timeout);
                        }
                        self.send_connection_request()?;
                        self.connection_request_time = Some(now);
                    }
                }
            }
            ConnectionState::Connected => {
                self.congestion
                    .update(self.stats.packet_loss, self.stats.rtt);
                self.congestion.refill_budget(self.config.mtu);

                if let Some(ref mut cw) = self.cwnd {
                    cw.update_pacing(self.reliability.rto());
                }

                let time_since_send = now.duration_since(self.last_packet_send_time);
                if time_since_send > self.config.keepalive_interval {
                    self.send_keepalive()?;
                }

                if let Some(probe_size) = self.mtu_discovery.next_probe() {
                    let header = self.create_header();
                    let padding = vec![0u8; probe_size.saturating_sub(16)];
                    let packet = Packet::new(
                        header,
                        PacketType::MtuProbe {
                            probe_size: probe_size as u16,
                        },
                    )
                    .with_payload(padding);
                    self.send_queue.push_back(packet);
                }

                self.data_sent_this_tick = false;
                let mut packets_sent_this_cycle: u32 = 0;
                for ch_idx_ref in 0..self.channel_priority_order.len() {
                    let ch_idx = self.channel_priority_order[ch_idx_ref];
                    loop {
                        let estimated_size = self.config.mtu;
                        if !self
                            .congestion
                            .can_send(packets_sent_this_cycle, estimated_size)
                        {
                            break;
                        }
                        // Check cwnd-based congestion if enabled
                        if let Some(ref cw) = self.cwnd {
                            if !cw.can_send(estimated_size) || !cw.can_send_paced(now) {
                                break;
                            }
                        }
                        let Some((msg_seq, wire_data)) =
                            self.channels[ch_idx].get_outgoing_message()
                        else {
                            break;
                        };
                        let packet_size = wire_data.len();
                        packets_sent_this_cycle += 1;
                        self.congestion.deduct_budget(packet_size);
                        let header = self.create_header();
                        let pkt_seq = header.sequence;

                        if wire_data.len() > self.config.fragment_threshold {
                            let frag_id = self.next_fragment_id;
                            self.next_fragment_id = self.next_fragment_id.wrapping_add(1);
                            if let Ok(fragments) = crate::fragment::fragment_message(
                                frag_id,
                                &wire_data,
                                self.config.fragment_threshold,
                            ) {
                                let mut frag_entries = Vec::with_capacity(fragments.len());
                                for (frag_idx, frag_data) in fragments.into_iter().enumerate() {
                                    let frag_header = self.create_header();
                                    let frag_pkt_seq = frag_header.sequence;
                                    let packet = Packet::new(
                                        frag_header,
                                        PacketType::Payload {
                                            channel: ch_idx as u8,
                                            is_fragment: true,
                                        },
                                    )
                                    .with_payload(frag_data.clone());
                                    self.send_queue.push_back(packet);
                                    frag_entries.push((frag_pkt_seq, frag_idx as u8, frag_data));
                                }
                                self.pending_fragments.insert(frag_id, frag_entries);
                            }
                        } else {
                            let packet = Packet::new(
                                header,
                                PacketType::Payload {
                                    channel: ch_idx as u8,
                                    is_fragment: false,
                                },
                            )
                            .with_payload(wire_data);
                            self.send_queue.push_back(packet);
                        }

                        self.data_sent_this_tick = true;
                        if let Some(ref mut cw) = self.cwnd {
                            cw.on_send(packet_size);
                        }
                        if self.channels[ch_idx].is_reliable() {
                            self.reliability.on_packet_sent(
                                pkt_seq,
                                now,
                                ch_idx as u8,
                                msg_seq,
                                packet_size,
                            );
                        }
                    }

                    let rto = self.reliability.rto();
                    let retransmits = self.channels[ch_idx].get_retransmit_messages(now, rto);
                    for (_seq, wire_data) in retransmits {
                        let header = self.create_header();
                        let packet = Packet::new(
                            header,
                            PacketType::Payload {
                                channel: ch_idx as u8,
                                is_fragment: false,
                            },
                        )
                        .with_payload(wire_data);
                        self.send_queue.push_back(packet);
                    }
                }

                for channel in &mut self.channels {
                    channel.update();
                }

                // Emit AckOnly if we have pending acks but didn't send any data this tick
                if self.pending_ack_send && !self.data_sent_this_tick {
                    let header = self.create_header();
                    let packet = Packet::new(header, PacketType::AckOnly);
                    self.send_queue.push_back(packet);
                }
                self.pending_ack_send = false;

                self.mtu_discovery.check_probe_timeout();
            }
            ConnectionState::Disconnecting => {
                if let Some(disc_time) = self.disconnect_time {
                    if now.duration_since(disc_time) > self.config.disconnect_retry_timeout {
                        if self.disconnect_retry_count >= self.config.disconnect_retries {
                            self.state = ConnectionState::Disconnected;
                            self.reset_connection();
                        } else {
                            self.disconnect_retry_count += 1;
                            self.disconnect_time = Some(now);
                            let header = self.create_header();
                            let packet = Packet::new(
                                header,
                                PacketType::Disconnect {
                                    reason: disconnect_reason::REQUESTED,
                                },
                            );
                            self.send_queue.push_back(packet);
                        }
                    }
                }
            }
            _ => {}
        }

        self.stats.rtt = self.reliability.srtt_ms() as f32;
        self.stats.packet_loss = self.reliability.packet_loss_percent();
        self.stats.bandwidth_up = self.bandwidth_up.bytes_per_second() as f32;
        self.stats.bandwidth_down = self.bandwidth_down.bytes_per_second() as f32;
        const LOSS_RATIO_TO_PERCENT: f32 = 100.0;
        self.stats.connection_quality = crate::stats::assess_connection_quality(
            self.stats.rtt,
            self.stats.packet_loss * LOSS_RATIO_TO_PERCENT,
        );

        Ok(())
    }

    fn send_keepalive(&mut self) -> Result<(), ConnectionError> {
        let header = self.create_header();
        let packet = Packet::new(header, PacketType::KeepAlive);
        self.send_queue.push_back(packet);
        Ok(())
    }

    fn process_send_queue(&mut self, socket: &mut UdpSocket) -> Result<(), ConnectionError> {
        while let Some(packet) = self.send_queue.pop_front() {
            let data = packet
                .serialize()
                .map_err(|_| ConnectionError::InvalidPacket)?;

            #[cfg(feature = "encryption")]
            let data = if let Some(ref enc) = self.encryption_state {
                enc.encrypt(&data, self.local_sequence as u64)
                    .unwrap_or(data)
            } else {
                data
            };

            let mut data_with_crc = data;
            security::append_crc32(&mut data_with_crc);

            socket.send_to(&data_with_crc, self.remote_addr)?;

            self.bandwidth_up.record(data_with_crc.len());
            self.last_packet_send_time = Instant::now();
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += data_with_crc.len() as u64;
        }
        Ok(())
    }

    fn receive_packets(&mut self, socket: &mut UdpSocket) -> Result<(), ConnectionError> {
        loop {
            match socket.recv_from() {
                Ok((data, addr)) => {
                    if addr != self.remote_addr {
                        continue;
                    }

                    let validated = match security::validate_and_strip_crc32(data) {
                        Some(valid) => valid,
                        None => continue,
                    };

                    #[cfg(feature = "encryption")]
                    let decrypted;
                    #[cfg(feature = "encryption")]
                    let validated = if let Some(ref enc) = self.encryption_state {
                        match enc.decrypt(validated, self.remote_sequence as u64) {
                            Ok(d) => {
                                decrypted = d;
                                &decrypted
                            }
                            Err(_) => continue,
                        }
                    } else {
                        validated
                    };

                    let packet = match Packet::deserialize(validated) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    if packet.header.protocol_id != self.config.protocol_id {
                        continue;
                    }

                    self.bandwidth_down.record(data.len());
                    self.last_packet_recv_time = Instant::now();
                    self.stats.packets_received += 1;
                    self.stats.bytes_received += data.len() as u64;

                    self.handle_packet(packet)?;
                }
                Err(SocketError::WouldBlock) => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
