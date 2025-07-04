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

use crate::crypto::{CryptoManager, CipherSuiteSelector};
use crate::fec::{AdaptiveFec, FecConfig, Packet as FecPacket, PidConfig};
use crate::optimize::{OptimizationManager, MemoryPool};
use crate::xdp_socket::XdpSocket;
use crate::stealth::{StealthManager, StealthConfig};
use std::collections::VecDeque;
use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

/// Represents a single QuicFuscate connection and manages its state.
pub struct QuicFuscateConnection {
    pub conn: quiche::Connection,
    pub peer_addr: SocketAddr,
    local_addr: SocketAddr,

    // Core Modules
    crypto_selector: CipherSuiteSelector,
    fec: AdaptiveFec,
    
    // Stealth & Optimization Modules
    stealth_manager: Arc<StealthManager>,
    optimization_manager: Arc<OptimizationManager>,

    // State
    stats: ConnectionStats,
    packet_id_counter: u64,
    handshake_start: Instant,
    // The outgoing buffer now holds fully formed FEC packets, ready for direct sending.
    // This eliminates the serialization overhead entirely.
    outgoing_fec_packets: VecDeque<FecPacket>,
    xdp_socket: Option<XdpSocket>,
}

/// Tracks performance and reliability metrics for a connection.
#[derive(Default, Debug)]
pub struct ConnectionStats {
    pub rtt: f32,
    pub loss_rate: f32,
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub fec_repair_generated: u64,
    pub fec_repair_received: u64,
    pub handshake_time_ms: Option<u128>,
}

/// Unified error type for core connection operations.
#[derive(Debug)]
pub enum CoreError {
    Quiche(quiche::Error),
    Io(std::io::Error),
    Other(String),
}

impl From<quiche::Error> for CoreError {
    fn from(e: quiche::Error) -> Self { CoreError::Quiche(e) }
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self { CoreError::Io(e) }
}

impl QuicFuscateConnection {
    /// Creates a new client connection.
    pub fn new_client(
        server_name: &str,
        remote_addr: SocketAddr,
        mut config: quiche::Config,
        stealth_config: StealthConfig,
    ) -> Result<Self, CoreError> {
        // --- Explicitly set BBRv2 Congestion Control as per PLAN.txt ---
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBRv2);
        // --- Enable MTU Discovery ---
        config.enable_mtu_probing();

        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::new());
        let stealth_manager = Arc::new(StealthManager::new(stealth_config, crypto_manager.clone(), optimization_manager.clone()));

        stealth_manager.apply_utls_profile(&mut config);
        
        let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);
        let local_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        
        let conn = quiche::connect(Some(server_name), &scid, local_addr, remote_addr, &mut config)
            .map_err(CoreError::from)?;
            
        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);
        Ok(Self::new(conn, local_addr, remote_addr, stealth_manager, optimization_manager, xdp_socket))
    }
    
    pub fn new_server(
        scid: &quiche::ConnectionId,
        odcid: Option<&quiche::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        mut config: quiche::Config,
        stealth_config: StealthConfig,
    ) -> Result<Self, CoreError> {
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBRv2);
        config.enable_mtu_probing();

        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::new());
        let stealth_manager = Arc::new(StealthManager::new(stealth_config, crypto_manager.clone(), optimization_manager.clone()));
        
        let conn = quiche::accept(scid, odcid, local_addr, remote_addr, &mut config)
            .map_err(CoreError::from)?;

        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);

        Ok(Self::new(conn, local_addr, remote_addr, stealth_manager, optimization_manager, xdp_socket))
    }

    fn new(
        conn: quiche::Connection,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        stealth_manager: Arc<StealthManager>,
        optimization_manager: Arc<OptimizationManager>,
        xdp_socket: Option<XdpSocket>,
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
        };

        Self {
            conn,
            peer_addr,
            local_addr,
            crypto_selector: CipherSuiteSelector::new(),
            fec: AdaptiveFec::new(fec_config, optimization_manager.clone()),
            stealth_manager,
            optimization_manager,
            stats: ConnectionStats::default(),
            packet_id_counter: 0,
            outgoing_fec_packets: VecDeque::new(),
            xdp_socket,
            handshake_start: Instant::now(),
        }
    }

    /// Processes an incoming raw buffer, parsing it into an FEC packet and handling recovery.
    /// This now avoids any serialization overhead.
    pub fn recv(&mut self, data: &mut [u8]) -> Result<usize, CoreError> {
        let len = if let Some(ref xdp) = self.xdp_socket {
            xdp.recv(data).map_err(CoreError::from)?
        } else {
            data.len()
        };

        let fec_packet = FecPacket::from_raw(self.packet_id_counter, &data[..len], &self.optimization_manager)
            .map_err(CoreError::Other)?;

        let recovered_packets = self.fec.on_receive(fec_packet)
            .map_err(|e| CoreError::Other(format!("FEC decoding failed: {}", e)))?;

        for mut packet in recovered_packets {
            self.stats.fec_repair_received += (!packet.is_systematic) as u64;
            // Deobfuscate payload if enabled
            self.stealth_manager.process_incoming_packet(&mut packet.data);
            
            // Process the reconstructed QUIC packet
            let recv_info = quiche::RecvInfo { from: self.peer_addr, to: self.local_addr };
            if let Err(e) = self.conn.recv(&mut packet.data, recv_info) {
                // Log error, but continue processing other recovered packets
                eprintln!("quiche::recv failed after FEC recovery: {}", e);
            }
            self.stats.bytes_received += packet.len as u64;
        }
        
        Ok(len)
    }
    
    /// Prepares QUIC packets for sending, wraps them in FEC, and buffers them.
    /// This has been completely refactored to eliminate serialization and copies.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, CoreError> {
        // If there are buffered FEC packets, send one directly.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            if let Some(ref xdp) = self.xdp_socket {
                xdp.send(&[&packet.data[..packet.len]])
                    .map_err(CoreError::from)?;
                self.stats.bytes_sent += packet.len as u64;
                return Ok(packet.len);
            } else {
                let written = packet.to_raw(buf)?;
                self.stats.bytes_sent += written as u64;
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
                return Err(CoreError::from(e));
            }
        };

        if write == 0 {
            self.optimization_manager.free_block(send_buffer);
            return Ok(0);
        }

        // Adjust buffer length to the actual data written.
        send_buffer[..write].iter_mut().for_each(|b| *b = 0);

        // Obfuscate payload if enabled
        self.stealth_manager.process_outgoing_packet(&mut send_buffer[..write]);

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
        let before = self.outgoing_fec_packets.len();
        self.fec.on_send(fec_packet, &mut self.outgoing_fec_packets);
        let after = self.outgoing_fec_packets.len();
        if after > before {
            // first packet is systematic
            self.stats.fec_repair_generated += (after - before - 1) as u64;
        }

        // Pop the first packet from the buffer to send it now.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            if let Some(ref xdp) = self.xdp_socket {
                xdp.send(&[&packet.data[..packet.len]])
                    .map_err(CoreError::from)?;
                self.stats.bytes_sent += packet.len as u64;
                Ok(packet.len)
            } else {
                let written = packet.to_raw(buf)?;
                self.stats.bytes_sent += written as u64;
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

        if self.stats.handshake_time_ms.is_none() && self.conn.is_established() {
            self.stats.handshake_time_ms = Some(self.handshake_start.elapsed().as_millis());
        }
        
        // Report stats to the adaptive FEC controller.
        self.fec.report_loss(stats.lost as usize, stats.sent as usize);

        // Handle path events for connection migration
        while let Some(e) = self.conn.path_event_next() {
            match e {
                quiche::PathEvent::New(addr) => {
                    println!("New path available: {}", addr);
                },
                quiche::PathEvent::Validated(addr) => {
                    println!("Path validated: {}", addr);
                    self.peer_addr = addr;
                },
                quiche::PathEvent::Closed(addr, e) => {
                    println!("Path {} closed: {}", addr, e);
                },
                quiche::PathEvent::Reused(addr) => {
                    println!("Path {} reused", addr);
                },
                quiche::PathEvent::Available(addr) => {
                    println!("Path {} available", addr);
                }
            }
        }
    }
}