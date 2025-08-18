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

use self::xdp_socket::XdpSocket;
use crate::crypto::{CipherSuiteSelector, CryptoManager};
use crate::fec::{AdaptiveFec, FecConfig, Packet as FecPacket};
use crate::optimize::{OptimizationManager, OptimizeConfig};
use crate::stealth::{StealthConfig, StealthManager};
use crate::telemetry;
use log::{debug, error, info, warn};
use quiche::h3::NameValue;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc; // for Header.name()/value()

/// Parameters for creating a new QuicFuscateConnection.
pub struct ConnectionParams {
    pub conn: quiche::Connection,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub host_header: String,
    pub stealth_manager: Arc<StealthManager>,
    pub optimization_manager: Arc<OptimizationManager>,
    pub xdp_socket: Option<XdpSocket>,
    pub fec_config: FecConfig,
}

/// Inlined module: xdp_socket (from src/xdp_socket.rs)
pub mod xdp_socket {
    #[cfg(unix)]
    use crate::optimize::ZeroCopyBuffer;
    use crate::telemetry;
    #[cfg(unix)]
    use std::io::{self, Error};
    #[cfg(unix)]
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::io::{AsRawFd, RawFd};

    #[cfg(all(unix, feature = "xdp"))]
    use thiserror::Error;

    #[cfg(all(unix, feature = "xdp"))]
    use {
        afxdp::{
            buf_mmap::BufMmap,
            mmap_area::{MmapArea, MmapAreaOptions},
            socket::{Socket, SocketOptions, SocketRx, SocketTx},
            umem::{Umem, UmemCompletionQueue, UmemFillQueue},
            PENDING_LEN,
        },
        arraydeque::{ArrayDeque, Wrapping},
        libbpf_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS},
        std::sync::Arc,
    };

    #[cfg(all(unix, feature = "xdp"))]
    struct XdpState {
        rx: SocketRx<'static, [u8; 2048]>,
        tx: SocketTx<'static, [u8; 2048]>,
        fq: UmemFillQueue<'static, [u8; 2048]>,
        cq: UmemCompletionQueue<'static, [u8; 2048]>,
        pool: Vec<BufMmap<'static, [u8; 2048]>>,
        pending: ArrayDeque<[BufMmap<'static, [u8; 2048]>; PENDING_LEN], Wrapping>,
    }

    #[cfg(all(unix, feature = "xdp"))]
    pub struct XdpSocket {
        udp: std::net::UdpSocket,
        state: Option<XdpState>,
    }

    #[cfg(all(unix, not(feature = "xdp")))]
    pub struct XdpSocket {
        socket: std::net::UdpSocket,
    }

    #[cfg(not(unix))]
    pub struct XdpSocket;

    #[cfg(all(unix, feature = "xdp"))]
    #[derive(Debug, Error)]
    pub enum XdpInitError {
        #[error("memory map failed")]
        Mmap,
        #[error("invalid ring size")]
        InvalidRing,
        #[error("umem setup failed: {0}")]
        Umem(#[source] io::Error),
        #[error("socket creation failed: {0}")]
        Socket(#[source] io::Error),
        #[error("kernel does not support AF_XDP")]
        Unsupported,
    }

    #[cfg(all(unix, feature = "xdp"))]
    fn is_unsupported(err: &io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS)
                | Some(libc::EOPNOTSUPP)
                | Some(libc::EPERM)
                | Some(libc::EINVAL)
                | Some(libc::ENODEV)
                | Some(libc::EAFNOSUPPORT)
        )
    }

    #[cfg(all(unix, feature = "xdp"))]
    impl From<afxdp::mmap_area::MmapError> for XdpInitError {
        fn from(_e: afxdp::mmap_area::MmapError) -> Self {
            XdpInitError::Mmap
        }
    }

    #[cfg(all(unix, feature = "xdp"))]
    impl From<afxdp::umem::UmemNewError> for XdpInitError {
        fn from(e: afxdp::umem::UmemNewError) -> Self {
            match e {
                afxdp::umem::UmemNewError::RingNotPowerOfTwo => XdpInitError::InvalidRing,
                afxdp::umem::UmemNewError::Create(err) => {
                    if is_unsupported(&err) {
                        XdpInitError::Unsupported
                    } else {
                        XdpInitError::Umem(err)
                    }
                }
            }
        }
    }

    #[cfg(all(unix, feature = "xdp"))]
    impl From<afxdp::socket::SocketNewError> for XdpInitError {
        fn from(e: afxdp::socket::SocketNewError) -> Self {
            match e {
                afxdp::socket::SocketNewError::RingNotPowerOfTwo => XdpInitError::InvalidRing,
                afxdp::socket::SocketNewError::Create(err) => {
                    if is_unsupported(&err) {
                        XdpInitError::Unsupported
                    } else {
                        XdpInitError::Socket(err)
                    }
                }
            }
        }
    }

    #[cfg(all(unix, feature = "xdp"))]
    fn init_state(iface: &str) -> Result<XdpState, XdpInitError> {
        const BUF_NUM: usize = 4096;
        const BUF_LEN: usize = 2048;
        let (area, mut bufs) =
            MmapArea::new(BUF_NUM, BUF_LEN, MmapAreaOptions { huge_tlb: false })?;
        let (umem, mut cq, mut fq) = Umem::new(
            area,
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
        )?;
        let (_socket, rx, tx) = Socket::new(
            umem.clone(),
            iface,
            0,
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
            SocketOptions::default(),
        )?;
        let _ = fq.fill(&mut bufs, bufs.len());
        Ok(XdpState {
            rx,
            tx,
            fq,
            cq,
            pool: bufs,
            pending: ArrayDeque::new(),
        })
    }

    #[cfg(all(unix, feature = "xdp"))]
    fn infer_iface(addr: &SocketAddr) -> String {
        if let Ok(iface) = std::env::var("XDP_IFACE") {
            return iface;
        }
        if addr.ip().is_loopback() {
            "lo".to_string()
        } else {
            "eth0".to_string()
        }
    }

    #[cfg(all(unix, feature = "xdp"))]
    impl XdpSocket {
        pub fn new_udp(bind: SocketAddr, remote: SocketAddr) -> io::Result<Self> {
            let socket = std::net::UdpSocket::bind(bind)?;
            socket.connect(remote)?;
            socket.set_nonblocking(true)?;
            telemetry!(telemetry::XDP_ACTIVE.set(0));
            Ok(Self {
                udp: socket,
                state: None,
            })
        }

        pub fn new(bind: SocketAddr, remote: SocketAddr) -> io::Result<Self> {
            let udp = std::net::UdpSocket::bind(bind)?;
            udp.connect(remote)?;
            udp.set_nonblocking(true)?;

            let iface = infer_iface(&bind);
            match init_state(&iface) {
                Ok(state) => {
                    telemetry!(telemetry::XDP_ACTIVE.set(1));
                    Ok(Self {
                        udp,
                        state: Some(state),
                    })
                }
                Err(XdpInitError::Unsupported) => {
                    telemetry!(telemetry::XDP_FALLBACKS.inc());
                    telemetry!(telemetry::XDP_ACTIVE.set(0));
                    Ok(Self { udp, state: None })
                }
                Err(e) => {
                    telemetry!(telemetry::XDP_FALLBACKS.inc());
                    telemetry!(telemetry::XDP_ACTIVE.set(0));
                    log::warn!("XDP initialization failed: {e}");
                    Ok(Self { udp, state: None })
                }
            }
        }

        pub fn reconfigure(&mut self, bind: SocketAddr, remote: SocketAddr) -> io::Result<()> {
            self.state.take();
            let udp = std::net::UdpSocket::bind(bind)?;
            udp.connect(remote)?;
            udp.set_nonblocking(true)?;

            let iface = infer_iface(&bind);
            match init_state(&iface) {
                Ok(state) => {
                    self.udp = udp;
                    self.state = Some(state);
                    telemetry!(telemetry::XDP_ACTIVE.set(1));
                    Ok(())
                }
                Err(XdpInitError::Unsupported) => {
                    telemetry!(telemetry::XDP_FALLBACKS.inc());
                    telemetry!(telemetry::XDP_ACTIVE.set(0));
                    self.udp = udp;
                    Ok(())
                }
                Err(e) => {
                    telemetry!(telemetry::XDP_FALLBACKS.inc());
                    telemetry!(telemetry::XDP_ACTIVE.set(0));
                    log::warn!("XDP reconfigure failed: {e}");
                    self.udp = udp;
                    Ok(())
                }
            }
        }

        fn fd(&self) -> RawFd {
            self.udp.as_raw_fd()
        }

        pub fn send(&mut self, buffers: &[&[u8]]) -> io::Result<usize> {
            use std::time::Instant;
            if let Some(state) = self.state.as_mut() {
                let start = Instant::now();
                if let Some(mut b) = state.pool.pop() {
                    let len = buffers.iter().map(|b| b.len()).sum::<usize>();
                    let data = buffers[0];
                    let copy_len = len.min(b.data.len());
                    b.data[..copy_len].copy_from_slice(&data[..copy_len]);
                    b.set_len(copy_len as u16);
                    let _ = state.pending.push_back(b);
                    let result = state.tx.try_send(&mut state.pending, 1);
                    let sent = result.unwrap_or(0);
                    let _ = state.cq.service(&mut state.pool, sent);
                    if sent == 1 {
                        telemetry!(telemetry::XDP_BYTES_SENT.inc_by(copy_len as u64));
                        telemetry!(
                            telemetry::XDP_SEND_LATENCY.inc_by(start.elapsed().as_micros() as u64)
                        );
                        let tput = (copy_len as u64 * 8 * 1_000_000)
                            / start.elapsed().as_micros().max(1) as u64;
                        telemetry!(telemetry::XDP_THROUGHPUT.set((tput / 1_000_000) as i64));
                        return Ok(copy_len);
                    } else if result.is_err() {
                        telemetry!(telemetry::XDP_FALLBACKS.inc());
                        telemetry!(telemetry::XDP_ACTIVE.set(0));
                        self.state = None;
                    }
                    state.pool.extend(state.pending.drain(..));
                }
            }
            let zc = ZeroCopyBuffer::new(buffers);
            let ret = zc.send(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                telemetry!(telemetry::BYTES_SENT.inc_by(ret as u64));
                Ok(ret as usize)
            }
        }

        pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::time::Instant;
            if let Some(state) = self.state.as_mut() {
                let start = Instant::now();
                let mut recvq: ArrayDeque<[BufMmap<[u8; 2048]>; PENDING_LEN], Wrapping> =
                    ArrayDeque::new();
                match state.rx.try_recv(&mut recvq, 1, [0u8; 2048]) {
                    Ok(n) if n > 0 => {
                        if let Some(mut b) = recvq.pop_front() {
                            let len = b.get_len() as usize;
                            let copy_len = len.min(buf.len());
                            buf[..copy_len].copy_from_slice(&b.data[..copy_len]);
                            let mut temp = vec![b];
                            let _ = state.fq.fill(&mut temp, 1);
                            telemetry!(telemetry::XDP_BYTES_RECEIVED.inc_by(copy_len as u64));
                            telemetry!(telemetry::XDP_RECV_LATENCY
                                .inc_by(start.elapsed().as_micros() as u64));
                            let tput = (copy_len as u64 * 8 * 1_000_000)
                                / start.elapsed().as_micros().max(1) as u64;
                            telemetry!(telemetry::XDP_THROUGHPUT.set((tput / 1_000_000) as i64));
                            return Ok(copy_len);
                        }
                    }
                    Err(_) => {
                        telemetry!(telemetry::XDP_FALLBACKS.inc());
                        telemetry!(telemetry::XDP_ACTIVE.set(0));
                        self.state = None;
                    }
                    _ => {}
                }
            }
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
            let ret = zc.recv(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                telemetry!(telemetry::BYTES_RECEIVED.inc_by(ret as u64));
                Ok(ret as usize)
            }
        }

        pub fn update_remote(&mut self, remote: SocketAddr) -> io::Result<()> {
            self.udp.connect(remote)
        }

        pub fn is_active(&self) -> bool {
            self.state.is_some()
        }
    }

    #[cfg(all(unix, not(feature = "xdp")))]
    impl XdpSocket {
        pub fn new(bind_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
            let socket = std::net::UdpSocket::bind(bind_addr)?;
            socket.connect(remote_addr)?;
            socket.set_nonblocking(true)?;
            telemetry!(telemetry::XDP_ACTIVE.set(0));
            Ok(Self { socket })
        }

        pub fn new_udp(bind_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
            Self::new(bind_addr, remote_addr)
        }

        pub fn is_active(&self) -> bool {
            false
        }

        fn fd(&self) -> RawFd {
            self.socket.as_raw_fd()
        }

        pub fn send(&self, buffers: &[&[u8]]) -> io::Result<usize> {
            let zc = ZeroCopyBuffer::new(buffers);
            let ret = zc.send(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                telemetry!(telemetry::BYTES_SENT.inc_by(ret as u64));
                Ok(ret as usize)
            }
        }

        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
            let ret = zc.recv(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                telemetry!(telemetry::BYTES_RECEIVED.inc_by(ret as u64));
                Ok(ret as usize)
            }
        }

        pub fn update_remote(&self, remote: SocketAddr) -> io::Result<()> {
            self.socket.connect(remote)
        }

        pub fn reconfigure(
            &mut self,
            bind_addr: SocketAddr,
            remote_addr: SocketAddr,
        ) -> io::Result<()> {
            let socket = std::net::UdpSocket::bind(bind_addr)?;
            socket.connect(remote_addr)?;
            socket.set_nonblocking(true)?;
            self.socket = socket;
            Ok(())
        }
    }

    #[cfg(not(unix))]
    impl XdpSocket {
        pub fn new(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn update_remote(&self, _remote: SocketAddr) -> io::Result<()> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn reconfigure(&mut self, _bind: SocketAddr, _remote: SocketAddr) -> io::Result<()> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn new_udp(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn is_active(&self) -> bool {
            false
        }
    }

    impl XdpSocket {
        pub fn is_supported() -> bool {
            cfg!(all(target_os = "linux", feature = "xdp"))
        }
    }
}

/// Inlined module: pq (from src/pq.rs)
#[cfg(feature = "pq")]
pub mod pq {
    #[cfg(feature = "pq")]
    use log::{error, warn};
    #[cfg(feature = "pq")]
    use pqcrypto_dilithium::dilithium3::{self, DetachedSignature};
    #[cfg(feature = "pq")]
    use pqcrypto_kyber::kyber768::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};

    /// Utilities for Post-Quantum key exchange and signatures using Kyber and Dilithium.
    #[cfg(feature = "pq")]
    pub struct PqCrypto;

    #[cfg(feature = "pq")]
    impl PqCrypto {
        /// Generates a Kyber768 keypair.
        pub fn kyber_keypair() -> (Vec<u8>, Vec<u8>) {
            let (pk, sk) = kyber768::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }

        /// Encapsulates a shared secret to the given Kyber768 public key.
        pub fn kyber_encapsulate(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
            match PublicKey::from_bytes(pk_bytes) {
                Ok(pk) => {
                    let (ss, ct) = kyber768::encapsulate(&pk);
                    (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
                }
                Err(e) => {
                    error!("kyber_encapsulate: invalid public key: {}", e);
                    (Vec::new(), Vec::new())
                }
            }
        }

        /// Decapsulates the Kyber768 ciphertext to recover the shared secret.
        pub fn kyber_decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
            let ct = match Ciphertext::from_bytes(ct_bytes) {
                Ok(v) => v,
                Err(e) => {
                    error!("kyber_decapsulate: invalid ciphertext: {}", e);
                    return Vec::new();
                }
            };
            let sk = match SecretKey::from_bytes(sk_bytes) {
                Ok(v) => v,
                Err(e) => {
                    error!("kyber_decapsulate: invalid secret key: {}", e);
                    return Vec::new();
                }
            };
            let ss = kyber768::decapsulate(&ct, &sk);
            ss.as_bytes().to_vec()
        }

        /// Generates a Dilithium3 keypair.
        pub fn dilithium_keypair() -> (Vec<u8>, Vec<u8>) {
            let (pk, sk) = dilithium3::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }

        /// Creates a Dilithium3 detached signature for the given message.
        pub fn dilithium_sign(msg: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
            match dilithium3::SecretKey::from_bytes(sk_bytes) {
                Ok(sk) => {
                    let sig = dilithium3::sign_detached(msg, &sk);
                    sig.as_bytes().to_vec()
                }
                Err(e) => {
                    error!("dilithium_sign: invalid secret key: {}", e);
                    Vec::new()
                }
            }
        }

        /// Verifies a Dilithium3 signature against the message.
        pub fn dilithium_verify(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
            let pk = match dilithium3::PublicKey::from_bytes(pk_bytes) {
                Ok(v) => v,
                Err(e) => {
                    error!("dilithium_verify: invalid public key: {}", e);
                    return false;
                }
            };
            let sig = match DetachedSignature::from_bytes(sig_bytes) {
                Ok(v) => v,
                Err(e) => {
                    error!("dilithium_verify: invalid signature: {}", e);
                    return false;
                }
            };
            dilithium3::verify_detached(&sig, msg, &pk).is_ok()
        }
    }
}

/// Represents a single QuicFuscate connection and manages its state.
pub struct QuicFuscateConnection {
    pub conn: quiche::Connection,
    pub peer_addr: SocketAddr,
    local_addr: SocketAddr,
    host_header: String,

    // Core Modules
    _crypto_selector: CipherSuiteSelector,
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
    last_telemetry: std::time::Instant,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new_client(
        server_name: &str,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        mut config: quiche::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        use_utls: bool,
    ) -> Result<Self, String> {
        // --- Explicitly set BBR2 Congestion Control ---
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBR2);

        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            crypto_manager.clone(),
            optimization_manager.clone(),
        ));

        let _ = stealth_manager.configure_tls(&mut config, use_utls, None);

        let scid = quiche::ConnectionId::from_ref(&[0; quiche::MAX_CONN_ID_LEN]);

        let (sni, host_header) = stealth_manager.get_connection_headers(server_name);

        let conn = quiche::connect(Some(&sni), &scid, local_addr, remote_addr, &mut config)
            .map_err(|e| format!("Failed to create QUIC connection: {}", e))?;

        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);
        Ok(Self::new(ConnectionParams {
            conn,
            local_addr,
            peer_addr: remote_addr,
            host_header,
            stealth_manager,
            optimization_manager,
            xdp_socket,
            fec_config,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        scid: &quiche::ConnectionId,
        odcid: Option<&quiche::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: &mut quiche::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
    ) -> Result<Self, String> {
        config.set_cc_algorithm(quiche::CongestionControlAlgorithm::BBR2);

        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            crypto_manager.clone(),
            optimization_manager.clone(),
        ));

        let conn = quiche::accept(scid, odcid, local_addr, remote_addr, config)
            .map_err(|e| format!("Failed to accept QUIC connection: {}", e))?;

        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);

        Ok(Self::new(ConnectionParams {
            conn,
            local_addr,
            peer_addr: remote_addr,
            host_header: String::new(),
            stealth_manager,
            optimization_manager,
            xdp_socket,
            fec_config,
        }))
    }

    fn new(
        params: ConnectionParams,
    ) -> Self {
        Self {
            conn: params.conn,
            peer_addr: params.peer_addr,
            local_addr: params.local_addr,
            host_header: params.host_header,
            _crypto_selector: CipherSuiteSelector::new(),
            fec: AdaptiveFec::new(params.fec_config, params.optimization_manager.memory_pool()),
            stealth_manager: params.stealth_manager,
            optimization_manager: params.optimization_manager,
            stats: ConnectionStats::default(),
            packet_id_counter: 0,
            outgoing_fec_packets: VecDeque::new(),
            xdp_socket: params.xdp_socket,
            h3_conn: None,
            last_telemetry: std::time::Instant::now(),
        }
    }

    /// Processes an incoming raw buffer, parsing it into an FEC packet and handling recovery.
    /// This now avoids any serialization overhead.
    pub fn recv(&mut self, data: &[u8]) -> Result<usize, crate::error::ConnectionError> {
        let mut block = self.optimization_manager.alloc_block();
        let len = if let Some(ref xdp) = self.xdp_socket {
            match xdp.recv(&mut block) {
                Ok(l) => l,
                Err(e) => {
                    self.optimization_manager.free_block(block);
                    return Err(crate::error::ConnectionError::Fec(e.to_string()));
                }
            }
        } else {
            let copy_len = data.len().min(block.len());
            block[..copy_len].copy_from_slice(&data[..copy_len]);
            copy_len
        };

        let fec_packet = FecPacket::from_block(
            self.packet_id_counter,
            block,
            len,
            &self.optimization_manager,
        )?;

        let recovered_packets = self.fec.on_receive(fec_packet).map_err(|e| {
            crate::error::ConnectionError::Fec(format!("FEC decoding failed: {}", e))
        })?;

        for mut packet in recovered_packets {
            if let Some(ref mut data_box) = packet.data {
                let data: &mut [u8] = &mut data_box[..packet.len];
                // Deobfuscate payload if enabled
                self.stealth_manager.process_incoming_packet(data);

                // Process the reconstructed QUIC packet
                let recv_info = quiche::RecvInfo {
                    from: self.peer_addr,
                    to: self.local_addr,
                };
                if let Err(e) = self.conn.recv(data, recv_info) {
                    // Log error, but continue processing other recovered packets
                    error!("quiche::recv failed after FEC recovery: {}", e);
                }
            }
        }

        Ok(len)
    }

    /// Prepares QUIC packets for sending, wraps them in FEC, and buffers them.
    /// This has been completely refactored to eliminate serialization and copies.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        // If there are buffered FEC packets, send one directly.
        if let Some(mut packet) = self.outgoing_fec_packets.pop_front() {
            let len = if let Some(ref xdp) = self.xdp_socket {
                // Prefer zero-copy from pooled buffer when available; otherwise materialize.
                if let Some(ref data) = packet.data {
                    let slice = &data[..packet.len];
                    xdp.send(&[slice])
                        .map_err(|e| crate::error::ConnectionError::Fec(e.to_string()))?;
                    packet.len
                } else {
                    let raw_len = packet.to_raw(buf)?;
                    xdp.send(&[&buf[..raw_len]])
                        .map_err(|e| crate::error::ConnectionError::Fec(e.to_string()))?;
                    raw_len
                }
            } else {
                packet.to_raw(buf)?
            };
            if let Some(data) = packet.data.take() {
                self.optimization_manager.free_block(data);
            }
            return Ok(len);
        }

        // Otherwise, generate a new QUIC packet using a pooled buffer.
        let mut send_buffer = self.optimization_manager.alloc_block();
        let (write, _send_info) = match self.conn.send(&mut send_buffer) {
            Ok(v) => v,
            Err(e) => {
                self.optimization_manager.free_block(send_buffer);
                return Err(crate::error::ConnectionError::Quiche(e));
            }
        };

        if write == 0 {
            self.optimization_manager.free_block(send_buffer);
            return Ok(0);
        }

        // The buffer may be larger than the written data; the length is tracked separately.

        // Obfuscate payload if enabled
        self.stealth_manager
            .process_outgoing_packet(&mut send_buffer[..write]);

        // Create a systematic FEC packet, passing ownership of the buffer.
        let fec_packet = FecPacket::new(
            self.packet_id_counter,
            Some(send_buffer),
            write,
            true,
            None,
            0,
            self.optimization_manager.memory_pool(),
        );
        self.packet_id_counter += 1;

        // Pass to FEC encoder to get original + repair packets.
        // The encoder now directly populates the outgoing queue.
        self.fec.on_send(fec_packet, &mut self.outgoing_fec_packets);

        // Pop the first packet from the buffer to send it now.
        if let Some(mut packet) = self.outgoing_fec_packets.pop_front() {
            let len = if let Some(ref xdp) = self.xdp_socket {
                if let Some(ref data) = packet.data {
                    let slice = &data[..packet.len];
                    xdp.send(&[slice])
                        .map_err(|e| crate::error::ConnectionError::Fec(e.to_string()))?;
                    packet.len
                } else {
                    let raw_len = packet.to_raw(buf)?;
                    xdp.send(&[&buf[..raw_len]])
                        .map_err(|e| crate::error::ConnectionError::Fec(e.to_string()))?;
                    raw_len
                }
            } else {
                packet.to_raw(buf)?
            };
            if let Some(data) = packet.data.take() {
                self.optimization_manager.free_block(data);
            }
            Ok(len)
        } else {
            Ok(0)
        }
    }

    /// Handles connection migration to a new network path.
    /// Triggers connection migration to a new peer address.
    ///
    /// The underlying QUIC connection will attempt to validate the new path
    /// and switch over once validation succeeds. Any error is returned so the
    /// caller can react accordingly.
    pub fn migrate_connection(&mut self, new_peer: SocketAddr) -> Result<u64, quiche::Error> {
        // Initiate path migration using quiche's API. The local address remains
        // unchanged, but a new peer address is supplied. quiche handles sending
        // the probing packets required for validation.
        self.xdp_socket = self
            .optimization_manager
            .create_xdp_socket(self.local_addr, new_peer);
        if let Some(ref xdp) = self.xdp_socket {
            let _ = xdp.update_remote(new_peer);
            telemetry!(telemetry::XDP_ACTIVE.set(1));
        } else {
            telemetry!(telemetry::XDP_ACTIVE.set(0));
        }

        let res = self.conn.migrate(self.local_addr, new_peer);
        if res.is_ok() {
            telemetry!(telemetry::PATH_MIGRATIONS.inc());
        }
        res
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
            // Enable a modest QPACK dynamic table to improve compression.
            let mut h3_cfg = quiche::h3::Config::new()?;
            h3_cfg.set_qpack_max_table_capacity(64 * 1024);
            h3_cfg.set_qpack_blocked_streams(16);

            let h3 = quiche::h3::Connection::with_transport(&mut self.conn, &h3_cfg)?;
            self.h3_conn = Some(h3);
        }
        Ok(())
    }

    /// Sends a masqueraded HTTP/3 GET request using the stealth manager.
    pub fn send_http3_request(&mut self, path: &str) -> Result<(), crate::error::ConnectionError> {
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
            let start = std::time::Instant::now();
            h3.send_request(&mut self.conn, &headers, true)?;
            info!("HTTP/3 request sent in {} ms", start.elapsed().as_millis());
        }
        Ok(())
    }

    /// Polls HTTP/3 events and prints received data.
    pub fn poll_http3(&mut self) -> Result<(), crate::error::ConnectionError> {
        if let Some(ref mut h3) = self.h3_conn {
            let start = std::time::Instant::now();
            loop {
                match h3.poll(&mut self.conn) {
                    Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        for h in list {
                            debug!(
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
                            debug!("Received {} bytes on stream {}", read, stream_id);
                            debug!("{}", String::from_utf8_lossy(data));
                        }
                    }
                    Ok((_id, quiche::h3::Event::Reset(err))) => {
                        warn!("H3 stream reset: {:?}", err);
                    }
                    Ok((_id, quiche::h3::Event::PriorityUpdate)) => {
                        debug!("H3 priority update received");
                    }
                    Ok((_id, quiche::h3::Event::GoAway)) => {
                        info!("H3 GOAWAY received");
                    }
                    Ok((_id, quiche::h3::Event::Finished)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }
            debug!(
                "HTTP/3 events processed in {} ms",
                start.elapsed().as_millis()
            );
        }
        Ok(())
    }

    /// Update internal state, e.g., FEC mode based on statistics.
    pub fn update_state(&mut self) {
        // Update stats (in a real app, this comes from the quiche connection)
        let stats = self.conn.stats();
        self.stats.packets_sent = stats.sent as u64;
        self.stats.packets_lost = stats.lost as u64;
        if stats.sent > 0 {
            self.stats.loss_rate = stats.lost as f32 / stats.sent as f32;
        }
        // quiche::Stats no longer exposes RTT directly. Use per-path stats and take the minimal RTT.
        self.stats.rtt = self
            .conn
            .path_stats()
            .map(|p| p.rtt)
            .min()
            .map(|d| d.as_millis() as f32)
            .unwrap_or(0.0);

        // Report stats to the adaptive FEC controller.
        self.fec.report_loss(stats.lost, stats.sent);

        if self.last_telemetry.elapsed() >= std::time::Duration::from_secs(1) {
            telemetry!(telemetry::update_memory_usage());
            telemetry!(telemetry::flush());
            self.last_telemetry = std::time::Instant::now();
        }

        // Handle path events for connection migration
        while let Some(event) = self.conn.path_event_next() {
            match event {
                quiche::PathEvent::New(local, peer) => {
                    info!("New path detected: {local}->{peer}");
                }
                quiche::PathEvent::Validated(local, peer) => {
                    info!("Path validated: {local}->{peer}");
                    self.peer_addr = peer;
                    self.local_addr = local;
                    if let Some(ref mut xdp) = self.xdp_socket {
                        if let Err(e) = xdp.reconfigure(local, peer) {
                            warn!("XDP reconfigure failed: {e}");
                            self.xdp_socket =
                                self.optimization_manager.create_xdp_socket(local, peer);
                        }
                    } else {
                        self.xdp_socket = self.optimization_manager.create_xdp_socket(local, peer);
                    }
                    telemetry!(telemetry::PATH_MIGRATIONS.inc());
                }
                quiche::PathEvent::FailedValidation(local, peer) => {
                    warn!("Path validation failed: {local}->{peer}");
                }
                quiche::PathEvent::Closed(local, peer) => {
                    info!("Path closed: {local}->{peer}");
                }
                quiche::PathEvent::ReusedSourceConnectionId(seq, old, new) => {
                    info!("CID {seq} reused from {old:?} to {new:?}");
                }
                quiche::PathEvent::PeerMigrated(local, peer) => {
                    info!("Peer migrated: {local}->{peer}");
                    self.peer_addr = peer;
                    self.local_addr = local;
                    if let Some(ref mut xdp) = self.xdp_socket {
                        if let Err(e) = xdp.reconfigure(local, peer) {
                            warn!("XDP reconfigure failed: {e}");
                            self.xdp_socket =
                                self.optimization_manager.create_xdp_socket(local, peer);
                        }
                    } else {
                        self.xdp_socket = self.optimization_manager.create_xdp_socket(local, peer);
                    }
                    telemetry!(telemetry::PATH_MIGRATIONS.inc());
                }
            }
        }
    }

    /// Returns the current estimated RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        self.stats.rtt
    }

    /// Returns the current estimated packet loss rate in [0.0, 1.0].
    pub fn loss_rate(&self) -> f32 {
        self.stats.loss_rate
    }
}
