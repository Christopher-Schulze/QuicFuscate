// Compatibility/test transport helpers.
//
// The former AF_XDP experiment was removed because it never implemented the
// kernel-backed UMEM and ring ownership contract. The remaining helpers are
// test-only segmentation and UDP fast-path compatibility coverage.

#[cfg(all(target_os = "linux", test))]
use libc::{c_void, socklen_t};
#[cfg(all(target_os = "linux", test))]
use std::mem;
// GSO/GRO offload helpers retained only for compatibility tests.
#[cfg(test)]
pub struct SegmentationOffload {
    gso_enabled: bool,
    gro_enabled: bool,
    max_gso_size: usize,
    max_gro_size: usize,
    current_batch_size: usize,
    adaptive_batching: bool,
}

#[cfg(test)]
impl Default for SegmentationOffload {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl SegmentationOffload {
    fn new() -> Self {
        Self {
            gso_enabled: Self::detect_gso_support(),
            gro_enabled: Self::detect_gro_support(),
            max_gso_size: 65536,
            max_gro_size: 65536,
            current_batch_size: 32,
            adaptive_batching: true,
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_gso_support() -> bool {
        // Check if GSO is available via UDP_SEGMENT socket option
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                return false;
            }
            let mut val: i32 = 0;
            let mut len = mem::size_of::<i32>() as socklen_t;
            let ret = libc::getsockopt(
                sock,
                libc::SOL_UDP,
                103, // UDP_SEGMENT
                &mut val as *mut _ as *mut c_void,
                &mut len,
            );
            libc::close(sock);
            ret == 0
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_gso_support() -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    fn detect_gro_support() -> bool {
        // Check if GRO is available via UDP_GRO socket option
        unsafe {
            let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if sock < 0 {
                return false;
            }
            let mut val: i32 = 0;
            let mut len = mem::size_of::<i32>() as socklen_t;
            let ret = libc::getsockopt(
                sock,
                libc::SOL_UDP,
                104, // UDP_GRO
                &mut val as *mut _ as *mut c_void,
                &mut len,
            );
            libc::close(sock);
            ret == 0
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_gro_support() -> bool {
        false
    }

    // Optimized userland GSO emulation for non-Linux platforms
    pub fn segment_packet(&self, data: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        if data.is_empty() || mtu == 0 {
            return Vec::new();
        }

        // Use configured max_gso_size if available
        let effective_mtu = if self.gso_enabled { mtu.min(self.max_gso_size) } else { mtu };

        // Adaptive batching: adjust batch size based on performance
        let _batch_hint = if self.adaptive_batching {
            self.current_batch_size
        } else {
            32 // Default batch size
        };

        // Pre-calculate number of segments for capacity
        let num_segments = data.len().div_ceil(effective_mtu);
        let mut segments = Vec::with_capacity(num_segments);
        let mut offset = 0;

        while offset < data.len() {
            let segment_size = (data.len() - offset).min(effective_mtu);

            let mut segment = Vec::with_capacity(segment_size);
            segment.extend_from_slice(&data[offset..offset + segment_size]);
            segments.push(segment);
            offset += segment_size;
        }

        segments
    }

    // Optimized userland GRO emulation
    pub fn coalesce_packets(&self, packets: Vec<Vec<u8>>) -> Vec<u8> {
        let mut total_size =
            packets.iter().fold(0usize, |total, packet| total.saturating_add(packet.len()));
        if self.gro_enabled {
            total_size = total_size.min(self.max_gro_size);
        }
        let mut coalesced = Vec::with_capacity(total_size);

        for packet in packets {
            let remaining = if self.gro_enabled {
                self.max_gro_size.saturating_sub(coalesced.len())
            } else {
                usize::MAX
            };
            if remaining == 0 {
                break;
            }
            let take = remaining.min(packet.len());
            coalesced.extend_from_slice(&packet[..take]);
            if self.gro_enabled && coalesced.len() >= self.max_gro_size {
                break;
            }
        }

        coalesced
    }
}

#[cfg(test)]
use std::collections::VecDeque;

/// Compatibility-only fastpath wrapper used by local tests.
#[cfg(test)]
struct FastPathTransport {
    udp_fast: Option<crate::transport::udpfast::UdpFastPath>,
    #[cfg(test)]
    segmentation: SegmentationOffload,
    #[cfg(test)]
    batch_queue: VecDeque<BatchedPacket>,
    #[cfg(test)]
    vectored_io_enabled: bool,
    default_peer: Option<std::net::SocketAddr>,
}

#[cfg(test)]
#[derive(Debug)]
struct BatchedPacket {
    data: Vec<u8>,
    addr: std::net::SocketAddr,
}

#[cfg(test)]
impl FastPathTransport {
    fn new() -> Self {
        Self {
            udp_fast: None,
            #[cfg(test)]
            segmentation: SegmentationOffload::new(),
            #[cfg(test)]
            batch_queue: VecDeque::new(),
            #[cfg(test)]
            vectored_io_enabled: true,
            default_peer: None,
        }
    }

    // XDP removed - use UDP fast path or io_uring instead

    #[cfg(test)]
    fn send_udp_refs_progress(
        udp: &mut crate::transport::udpfast::UdpFastPath,
        packet_refs: &[(&[u8], std::net::SocketAddr)],
    ) -> (usize, Option<std::io::Error>) {
        let mut sent_total = 0usize;
        while sent_total < packet_refs.len() {
            match udp.send_batch(&packet_refs[sent_total..]) {
                Ok(0) => {
                    return (
                        sent_total,
                        Some(std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "UDP fast path sent zero packets",
                        )),
                    );
                }
                Ok(sent) => {
                    sent_total += sent;
                }
                Err(err) => return (sent_total, Some(err)),
            }
        }
        (sent_total, None)
    }

    #[cfg(test)]
    fn flush_batch(&mut self) -> Result<(), std::io::Error> {
        if self.batch_queue.is_empty() {
            return Ok(());
        }

        let packets: Vec<BatchedPacket> = self.batch_queue.drain(..).collect();

        // Send via UDP fast path if available
        if let Some(ref mut udp) = self.udp_fast {
            let (sent_total, send_err) = {
                let packet_refs: Vec<_> =
                    packets.iter().map(|p| (p.data.as_slice(), p.addr)).collect();
                Self::send_udp_refs_progress(udp, &packet_refs)
            };

            if sent_total < packets.len() {
                for packet in packets.into_iter().skip(sent_total).rev() {
                    self.batch_queue.push_front(packet);
                }
            }

            if let Some(err) = send_err {
                return Err(err);
            }

            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "UDP fast path not configured",
            ))
        }
    }

    #[cfg(test)]
    fn send_segmented_fastpath(&mut self, data: &[u8], mtu: usize) -> Result<(), std::io::Error> {
        // Use vectored I/O if enabled for better batching
        if self.vectored_io_enabled {
            let peer = self.default_peer.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "Fast path peer not set")
            })?;
            let packet = BatchedPacket { data: data.to_vec(), addr: peer };
            self.batch_queue.push_back(packet);
            // Reliability-first semantics: ensure packets are actually emitted per call.
            // flush_batch still preserves multi-packet handling when queue is already populated.
            return self.flush_batch();
        }

        let segments = self.segmentation.segment_packet(data, mtu);

        if let Some(ref mut udp) = self.udp_fast {
            let peer = self.default_peer.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "Fast path peer not set")
            })?;
            let (sent_total, send_err) = {
                let packet_refs: Vec<_> = segments.iter().map(|seg| (seg.as_ref(), peer)).collect();
                Self::send_udp_refs_progress(udp, &packet_refs)
            };
            if sent_total < segments.len() {
                return Err(send_err.unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "UDP fast path partial segment batch send",
                    )
                }));
            }
            if let Some(err) = send_err {
                return Err(err);
            }
            return Ok(());
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "No fast path transport configured",
        ))
    }

    #[cfg(test)]
    fn send_segmented_compat(&mut self, data: &[u8], mtu: usize) -> Result<(), std::io::Error> {
        self.send_segmented_fastpath(data, mtu)
    }

    #[cfg(test)]
    fn recv_coalesced_fastpath(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        if let Some(ref mut udp) = self.udp_fast {
            let packets = udp.recv_batch(self.segmentation.current_batch_size.max(1))?;
            if packets.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "no packets available on UDP fast path",
                ));
            }

            let coalesced = self
                .segmentation
                .coalesce_packets(packets.into_iter().map(|(data, _)| data).collect());
            if coalesced.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "coalesced receive buffer is empty",
                ));
            }

            let n = coalesced.len().min(buf.len());
            buf[..n].copy_from_slice(&coalesced[..n]);
            return Ok(n);
        }

        // Fallback
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No fast path enabled"))
    }

    fn enable_udp_fastpath(
        &mut self,
        bind: std::net::SocketAddr,
        peer: std::net::SocketAddr,
    ) -> Result<(), std::io::Error> {
        let udp = crate::transport::udpfast::UdpFastPath::new(bind)?;
        self.udp_fast = Some(udp);
        self.default_peer = Some(peer);
        log::info!("UDP fast path enabled (bind={}, peer={})", bind, peer);
        Ok(())
    }

    /// Enable the best available fast-path based on environment configuration.
    ///
    /// QUICFUSCATE_FASTPATH = "off" | "auto" (default: auto)
    /// This compat/test shim keeps only the narrowed UDP fastpath coverage
    /// used by local tests.
    #[inline]
    fn enable_fastpath_from_env(&mut self, bind: std::net::SocketAddr, peer: std::net::SocketAddr) {
        self.default_peer = Some(peer);
        match crate::interface::FastpathMode::from_env() {
            crate::interface::FastpathMode::Off => { /* no-op */ }
            crate::interface::FastpathMode::Auto => {
                if let Err(e) = self.enable_udp_fastpath(bind, peer) {
                    log::warn!("UDP fast path enable failed: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
impl Default for FastPathTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod fastpath_udp_tests {
    use super::{FastPathTransport, SegmentationOffload};
    use crate::transport::udpfast::MAX_BATCH_SIZE;
    use std::env;
    use std::net::UdpSocket;
    use std::sync::MutexGuard;
    use std::time::Duration;

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = env::var(key).ok();
            env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = self.prev.take() {
                env::set_var(self.key, prev);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    fn udp_fastpath_lock() -> MutexGuard<'static, ()> {
        crate::env_utils::test_support::acquire_env_lock()
    }

    #[test]
    fn segmentation_rejects_zero_mtu_without_panicking() {
        let segmentation = SegmentationOffload::new();
        assert!(segmentation.segment_packet(b"payload", 0).is_empty());
    }

    #[test]
    fn auto_mode_falls_back_to_udp_fastpath_when_uring_unavailable() {
        let _env_lock = udp_fastpath_lock();
        let _guard = EnvGuard::set("QUICFUSCATE_FASTPATH", "auto");

        let mut fp = FastPathTransport::new();
        let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("bind parse");
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().expect("peer parse");
        fp.enable_fastpath_from_env(bind, peer);

        assert!(fp.udp_fast.is_some(), "auto mode must enable UDP fastpath");
    }

    #[test]
    fn send_segmented_compat_udp_path_sends_all_segments_over_multiple_batches() {
        let _udp_lock = udp_fastpath_lock();
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set read timeout");
        let recv_addr = receiver.local_addr().expect("receiver local addr");

        let mut fp = FastPathTransport::new();
        fp.enable_udp_fastpath("127.0.0.1:0".parse().expect("bind parse"), recv_addr)
            .expect("enable udp fastpath");
        fp.vectored_io_enabled = false;

        let mtu = 1200usize;
        let expected_segments = MAX_BATCH_SIZE + 5;
        let payload = vec![0xABu8; mtu * expected_segments];

        fp.send_segmented_compat(&payload, mtu).expect("send_segmented_compat");

        let mut recv_segments = 0usize;
        let mut recv_bytes = 0usize;
        while recv_segments < expected_segments {
            let mut buf = [0u8; 1400];
            let (n, _) = receiver.recv_from(&mut buf).expect("recv segment");
            assert!(n <= mtu, "segment larger than mtu");
            recv_segments += 1;
            recv_bytes += n;
        }

        assert_eq!(recv_segments, expected_segments, "segment count mismatch");
        assert_eq!(recv_bytes, payload.len(), "total received bytes mismatch");
    }

    #[test]
    fn unsupported_fastpath_value_defaults_to_udp_fastpath_auto_policy() {
        let _env_lock = udp_fastpath_lock();
        let _guard = EnvGuard::set("QUICFUSCATE_FASTPATH", "legacy-fastpath");

        let mut fp = FastPathTransport::new();
        let bind: std::net::SocketAddr = "127.0.0.1:0".parse().expect("bind parse");
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().expect("peer parse");
        fp.enable_fastpath_from_env(bind, peer);

        assert!(
            fp.udp_fast.is_some(),
            "unsupported fastpath values must fall back to the canonical auto policy"
        );
    }

    #[test]
    fn recv_coalesced_fastpath_reads_from_udp_fastpath() {
        let _udp_lock = udp_fastpath_lock();
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender.set_write_timeout(Some(Duration::from_secs(1))).expect("set write timeout");

        let mut fp = FastPathTransport::new();
        fp.enable_udp_fastpath(
            "127.0.0.1:0".parse().expect("bind parse"),
            "127.0.0.1:9".parse().expect("peer parse"),
        )
        .expect("enable udp fastpath");

        let recv_addr =
            fp.udp_fast.as_ref().expect("udp fastpath").local_addr().expect("udp local addr");
        let payload = b"recv-with-gro-fastpath";
        sender.send_to(payload, recv_addr).expect("send payload");

        let mut out = [0u8; 256];
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            match fp.recv_coalesced_fastpath(&mut out) {
                Ok(n) => {
                    assert_eq!(n, payload.len(), "unexpected receive length");
                    assert_eq!(&out[..n], payload, "payload mismatch");
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "timed out waiting for UDP fastpath receive"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("recv_coalesced_fastpath failed: {}", err),
            }
        }
    }

    #[test]
    fn send_segmented_compat_flushes_single_packet_when_vectored_enabled() {
        let _udp_lock = udp_fastpath_lock();
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set read timeout");
        let recv_addr = receiver.local_addr().expect("receiver local addr");

        let mut fp = FastPathTransport::new();
        fp.enable_udp_fastpath("127.0.0.1:0".parse().expect("bind parse"), recv_addr)
            .expect("enable udp fastpath");
        fp.vectored_io_enabled = true;

        let payload = b"single-packet-flush";
        fp.send_segmented_compat(payload, 1200).expect("send_segmented_compat");

        let mut buf = [0u8; 128];
        let (n, _) = receiver.recv_from(&mut buf).expect("recv packet");
        assert_eq!(n, payload.len(), "unexpected received payload length");
        assert_eq!(&buf[..n], payload, "received payload mismatch");
        assert!(
            fp.batch_queue.is_empty(),
            "batch queue must be empty after immediate flush semantics"
        );
    }
}
