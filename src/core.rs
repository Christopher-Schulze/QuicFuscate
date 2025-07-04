// Copyright (c) 2024, The QuicFuscate Project Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following disclaimer
//       in the documentation and/or other materials provided with the
//       distribution.
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # Core Connection Manager
//!
//! This module provides the central `QuicFuscateConnection` struct, which
//! orchestrates the crypto, FEC, and stealth modules to manage a full
//! QUIC connection lifecycle.

use crate::crypto::{CipherSuiteSelector, CryptoManager};
use crate::fec::{AdaptiveFec, FecConfig, Packet as FecPacket, PidConfig};
use crate::optimize::{MemoryPool, OptimizationManager};
use crate::stealth::{StealthConfig, StealthManager};
use crate::xdp_socket::XdpSocket;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

/// Represents a single QuicFuscate connection and manages its state.
pub struct QuicFuscateConnection {
    pub conn: quiche::Connection,
    pub peer_addr: SocketAddr,
    local_addr: SocketAddr,
    host_header: String,

    // Core Modules
    crypto_selector: CipherSuiteSelector,
    fec: AdaptiveFec,

    // Stealth & Optimization Modules
    stealth_manager: Arc<StealthManager>,
    optimization_manager: Arc<OptimizationManager>,

    // State
    stats: ConnectionStats,
    packet_id_counter: u64,
    // The outgoing buffer now holds fully formed FEC packets, ready for direct sending.
    // This eliminates the serialization overhead entirely.
    outgoing_fec_packets: VecDeque<FecPacket>,
    xdp_socket: Option<XdpSocket>,
    h3_conn: Option<quiche::h3::Connection>,
}

/// Tracks performance and reliability metrics for a connection.
#[derive(Default, Debug)]
pub struct ConnectionStats {
    pub rtt: f32,
    pub loss_rate: f32,
    pub packets_sent: u64,
    pub packets_lost: u64,
}

impl QuicFuscateConnection {
    /// Creates a new client connection.
    pub fn new_client(
        server_name: &str,
        remote_addr: SocketAddr,
        mut config: quiche::Config,
        stealth_config: StealthConfig,
        fec_mode: FecMode,
    ) -> Result<Self, String> {
        // --- Explicitly set BBRv2 Congestion Control as per PLAN.txt ---
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBRv2);
        // --- Enable MTU Discovery ---
        config.enable_mtu_probing();

        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::new());
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            crypto_manager.clone(),
            optimization_manager.clone(),
        ));

        stealth_manager.apply_utls_profile(&mut config);

        let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
        let local_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

        let (sni, host_header) = stealth_manager.get_connection_headers(server_name);

        let conn = quiche::connect(Some(&sni), &scid, local_addr, remote_addr, &mut config)
            .map_err(|e| format!("Failed to create QUIC connection: {}", e))?;

        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);
        Ok(Self::new(
            conn,
            local_addr,
            remote_addr,
            host_header,
            stealth_manager,
            optimization_manager,
            xdp_socket,
            fec_mode,
        ))
    }

    pub fn new_server(
        scid: &quiche::ConnectionId,
        odcid: Option<&quiche::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        mut config: quiche::Config,
        stealth_config: StealthConfig,
        fec_mode: FecMode,
    ) -> Result<Self, String> {
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBRv2);
        config.enable_mtu_probing();

        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::new());
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            crypto_manager.clone(),
            optimization_manager.clone(),
        ));

        let conn = quiche::accept(scid, odcid, local_addr, remote_addr, &mut config)
            .map_err(|e| format!("Failed to accept QUIC connection: {}", e))?;

        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);

        Ok(Self::new(
            conn,
            local_addr,
            remote_addr,
            String::new(),
            stealth_manager,
            optimization_manager,
            xdp_socket,
            fec_mode,
        ))
    }

    fn new(
        conn: quiche::Connection,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        host_header: String,
        stealth_manager: Arc<StealthManager>,
        optimization_manager: Arc<OptimizationManager>,
        xdp_socket: Option<XdpSocket>,
        fec_mode: FecMode,
    ) -> Self {
        let fec_config = FecConfig {
            lambda: 0.1,
            burst_window: 20,
            hysteresis: 0.02,
            pid: PidConfig {
                kp: 0.5,
                ki: 0.1,
                kd: 0.2,
            },
            initial_mode: fec_mode,
            window_sizes: FecConfig::default_windows(),
        };

        Self {
            conn,
            peer_addr,
            local_addr,
            host_header,
            crypto_selector: CipherSuiteSelector::new(),
            fec: AdaptiveFec::new(fec_config, optimization_manager.memory_pool()),
            stealth_manager,
            optimization_manager,
            stats: ConnectionStats::default(),
            packet_id_counter: 0,
            outgoing_fec_packets: VecDeque::new(),
            xdp_socket,
            h3_conn: None,
        }
    }

    /// Processes an incoming raw buffer, parsing it into an FEC packet and handling recovery.
    /// This now avoids any serialization overhead.
    pub fn recv(&mut self, data: &mut [u8]) -> Result<usize, String> {
        let len = if let Some(ref xdp) = self.xdp_socket {
            xdp.recv(data).map_err(|e| e.to_string())?
        } else {
            data.len()
        };

        let fec_packet = FecPacket::from_raw(
            self.packet_id_counter,
            &data[..len],
            &self.optimization_manager,
        )?;

        let recovered_packets = self
            .fec
            .on_receive(fec_packet)
            .map_err(|e| format!("FEC decoding failed: {}", e))?;

        for mut packet in recovered_packets {
            // Deobfuscate payload if enabled
            self.stealth_manager
                .process_incoming_packet(&mut packet.data);

            // Process the reconstructed QUIC packet
            let recv_info = quiche::RecvInfo {
                from: self.peer_addr,
                to: self.local_addr,
            };
            if let Err(e) = self.conn.recv(&mut packet.data, recv_info) {
                // Log error, but continue processing other recovered packets
                eprintln!("quiche::recv failed after FEC recovery: {}", e);
            }
        }

        Ok(len)
    }

    /// Prepares QUIC packets for sending, wraps them in FEC, and buffers them.
    /// This has been completely refactored to eliminate serialization and copies.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, quiche::Error> {
        // If there are buffered FEC packets, send one directly.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            if let Some(ref xdp) = self.xdp_socket {
                xdp.send(&[&packet.data[..packet.len]])
                    .map_err(|_| quiche::Error::Done)?;
                return Ok(packet.len);
            } else {
                let written = packet.to_raw(buf)?;
                return Ok(written);
            }
        }

        // Otherwise, generate a new QUIC packet using a pooled buffer.
        let mut send_buffer = self.optimization_manager.alloc_block();
        let (write, _send_info) = match self.conn.send(&mut send_buffer) {
            Ok(v) => v,
            Err(e) => {
                // Return buffer to the pool on failure
                self.optimization_manager.free_block(send_buffer);
                return Err(e);
            }
        };

        if write == 0 {
            self.optimization_manager.free_block(send_buffer);
            return Ok(0);
        }

        // Adjust buffer length to the actual data written.
        send_buffer[..write].iter_mut().for_each(|b| *b = 0);

        // Obfuscate payload if enabled
        self.stealth_manager
            .process_outgoing_packet(&mut send_buffer[..write]);

        // Create a systematic FEC packet, passing ownership of the buffer.
        let fec_packet = FecPacket {
            id: self.packet_id_counter,
            data: send_buffer,
            len: write,
            is_systematic: true,
            coefficients: None,
        };
        self.packet_id_counter += 1;

        // Pass to FEC encoder to get original + repair packets.
        // The encoder now directly populates the outgoing queue.
        self.fec.on_send(fec_packet, &mut self.outgoing_fec_packets);

        // Pop the first packet from the buffer to send it now.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            if let Some(ref xdp) = self.xdp_socket {
                xdp.send(&[&packet.data[..packet.len]])
                    .map_err(|_| quiche::Error::Done)?;
                Ok(packet.len)
            } else {
                let written = packet.to_raw(buf)?;
                Ok(written)
            }
        } else {
            Ok(0)
        }
    }

    /// Handles connection migration to a new network path.
    pub fn migrate_connection(&mut self, new_addr: SocketAddr) {
        self.conn.on_validation(quiche::PathEvent::New(new_addr));
        // Probing the new path is necessary to ensure it's viable.
        // The actual send/recv loop will handle the probe packets.
    }

    /// Returns the Host header that should be used for HTTP requests when domain
    /// fronting is active.
    pub fn host_header(&self) -> &str {
        &self.host_header
    }

    /// Returns the stealth manager for dynamic profile updates.
    pub fn stealth_manager(&self) -> Arc<StealthManager> {
        self.stealth_manager.clone()
    }

    /// Initializes the HTTP/3 connection if it hasn't been created yet.
    pub fn init_http3(&mut self) -> Result<(), quiche::h3::Error> {
        if self.h3_conn.is_none() {
            let h3_cfg = quiche::h3::Config::new()?;
            let h3 = quiche::h3::Connection::with_transport(&mut self.conn, &h3_cfg)?;
            self.h3_conn = Some(h3);
        }
        Ok(())
    }

    /// Sends a masqueraded HTTP/3 GET request using the stealth manager.
    pub fn send_http3_request(&mut self, path: &str) -> Result<(), quiche::h3::Error> {
        self.init_http3()?;
        let host = self.host_header.clone();
        let headers = self
            .stealth_manager
            .get_http3_header_list(&host, path)
            .unwrap_or_else(|| {
                vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", host.as_bytes()),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                ]
            });

        if let Some(ref mut h3) = self.h3_conn {
            h3.send_request(&mut self.conn, &headers, true)?;
        }
        Ok(())
    }

    /// Polls HTTP/3 events and prints received data.
    pub fn poll_http3(&mut self) -> Result<(), quiche::h3::Error> {
        if let Some(ref mut h3) = self.h3_conn {
            loop {
                match h3.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        for h in list {
                            println!(
                                "{}: {}",
                                String::from_utf8_lossy(h.name()),
                                String::from_utf8_lossy(h.value())
                            );
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let mut buf = [0; 4096];
                        while let Ok(read) = h3.recv_body(&mut self.conn, stream_id, &mut buf) {
                            let data = &buf[..read];
                            println!("Received {} bytes on stream {}", read, stream_id);
                            println!("{}", String::from_utf8_lossy(data));
                        }
                    }
                    Ok((_id, quiche::h3::Event::Finished)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Update internal state, e.g., FEC mode based on statistics.
    pub fn update_state(&mut self) {
        // Update stats (in a real app, this comes from the quiche connection)
        let stats = self.conn.stats();
        self.stats.packets_sent = stats.sent;
        self.stats.packets_lost = stats.lost;
        if stats.sent > 0 {
            self.stats.loss_rate = stats.lost as f32 / stats.sent as f32;
        }
        self.stats.rtt = stats.rtt.as_millis() as f32;

        // Report stats to the adaptive FEC controller.
        self.fec
            .report_loss(stats.lost as usize, stats.sent as usize);

        // Handle path events for connection migration
        while let Some(e) = self.conn.path_event_next() {
            match e {
                quiche::PathEvent::New(addr) => {
                    println!("New path available: {}", addr);
                }
                quiche::PathEvent::Validated(addr) => {
                    println!("Path validated: {}", addr);
                    self.peer_addr = addr;
                }
                quiche::PathEvent::Closed(addr, e) => {
                    println!("Path {} closed: {}", addr, e);
                }
                quiche::PathEvent::Reused(addr) => {
                    println!("Path {} reused", addr);
                }
                quiche::PathEvent::Available(addr) => {
                    println!("Path {} available", addr);
                }
            }
        }
    }
}
