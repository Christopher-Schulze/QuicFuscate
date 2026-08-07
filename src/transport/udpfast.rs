use std::net::UdpSocket;

use crate::optimize::{prefetch, PrefetchHint};
// Maximum sophisticated UDP fast path
// Batching, vectored I/O, GSO/GRO, prefetch, branch hints

use std::io;
#[cfg(target_os = "linux")]
use std::mem;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use smallvec::SmallVec;

// Linux-specific imports
#[cfg(target_os = "linux")]
use libc::{
    c_void, iovec, mmsghdr, msghdr, recvmmsg, sockaddr_storage, timespec, CMSG_DATA, CMSG_FIRSTHDR,
    CMSG_LEN, CMSG_SPACE, MSG_DONTWAIT, SOL_UDP, UDP_GRO, UDP_SEGMENT,
};

// Telemetry

// Maximum batch sizes
pub const MAX_BATCH_SIZE: usize = 64;

// Cache line size for alignment
const CACHE_LINE_SIZE: usize = 64;

// Prefetch hints
#[cfg_attr(feature = "aggressive_inline", inline(always))]
fn prefetch_outbound_payload(ptr: *const u8) {
    prefetch(ptr, PrefetchHint::T0);
}

// Branch prediction hints
#[inline(always)]
#[cold]
fn cold_path() {}

#[inline(always)]
pub(crate) fn likely(b: bool) -> bool {
    if !b {
        cold_path();
    }
    b
}

#[inline(always)]
pub(crate) fn unlikely(b: bool) -> bool {
    if b {
        cold_path();
    }
    b
}

// Aligned buffer for zero-copy
#[repr(align(64))]
pub(crate) struct AlignedBuffer {
    data: Vec<u8>,
}

impl AlignedBuffer {
    pub(crate) fn try_new(size: usize) -> io::Result<Self> {
        let aligned_size = size.checked_add(CACHE_LINE_SIZE - 1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "aligned buffer size overflow")
        })? & !(CACHE_LINE_SIZE - 1);
        let mut data = Vec::new();
        data.try_reserve_exact(aligned_size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("unable to reserve {aligned_size} bytes for aligned UDP buffer"),
            )
        })?;
        data.resize(aligned_size, 0);
        Ok(Self { data })
    }

    #[inline(always)]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    #[inline(always)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(any(test, feature = "rust-tests"))]
pub fn aligned_buffer_len_for_rust_tests(size: usize) -> io::Result<usize> {
    Ok(AlignedBuffer::try_new(size)?.as_slice().len())
}

pub struct UdpFastPath {
    socket: UdpSocket,
    #[cfg(target_os = "linux")]
    fd: RawFd,
    gso_enabled: bool,
    gro_enabled: bool,

    // Buffers for batching
    recv_batch: Vec<AlignedBuffer>,

    // Statistics
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
}

impl UdpFastPath {
    pub fn new(bind: SocketAddr) -> io::Result<Self> {
        Self::new_with_flags(bind, true, true)
    }

    /// Create a new UDP fast path with explicit GSO/GRO enable flags.
    /// Pass `gso_requested=false` or `gro_requested=false` to disable the offload
    /// even on platforms that support it.
    pub fn new_with_flags(
        bind: SocketAddr,
        gso_requested: bool,
        gro_requested: bool,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        let fd = socket.as_raw_fd();

        let mut fast_path = Self {
            socket,
            #[cfg(target_os = "linux")]
            fd,
            gso_enabled: false,
            gro_enabled: false,
            recv_batch: Vec::with_capacity(MAX_BATCH_SIZE),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        };

        // Pre-allocate aligned buffers
        for _ in 0..MAX_BATCH_SIZE {
            fast_path.recv_batch.push(AlignedBuffer::try_new(65536)?);
        }

        // Enable features as supported on this platform and requested by config.
        if gso_requested {
            fast_path.enable_gso();
        }
        if gro_requested {
            fast_path.enable_gro();
        }
        Ok(fast_path)
    }

    #[cfg(target_os = "linux")]
    fn enable_gso(&mut self) {
        unsafe {
            // UDP_SEGMENT is a segment-size knob, not a boolean. Probe support only;
            // send_gso() supplies the actual per-message segment size.
            let mut val: i32 = 0;
            let mut len = mem::size_of::<i32>() as libc::socklen_t;
            let ret = libc::getsockopt(
                self.fd,
                SOL_UDP,
                UDP_SEGMENT,
                &mut val as *mut _ as *mut c_void,
                &mut len,
            );
            self.gso_enabled = ret == 0;
            if self.gso_enabled {
                log::info!("UDP GSO enabled");
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn enable_gro(&mut self) {
        unsafe {
            let val: i32 = 1;
            let ret = libc::setsockopt(
                self.fd,
                SOL_UDP,
                UDP_GRO,
                &val as *const _ as *const c_void,
                mem::size_of_val(&val) as libc::socklen_t,
            );
            self.gro_enabled = ret == 0;
            if self.gro_enabled {
                log::info!("UDP GRO enabled");
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn enable_gso(&mut self) {
        // Not available on non-Linux, but track intent
        self.gso_enabled = false;
    }

    #[cfg(not(target_os = "linux"))]
    fn enable_gro(&mut self) {
        self.gro_enabled = false;
    }

    // Sophisticated batched send - cross-platform optimized.
    // All variants return packet count; byte accounting stays in internal counters.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        if unlikely(packets.is_empty()) {
            return Ok(0);
        }
        let batch_packets = &packets[..packets.len().min(MAX_BATCH_SIZE)];

        // Fast path for single packet
        if batch_packets.len() == 1 {
            self.send_single(batch_packets[0].0, batch_packets[0].1)?;
            return Ok(1);
        }

        for window in batch_packets.windows(2) {
            prefetch_outbound_payload(window[1].0.as_ptr());
        }

        let sent_count = crate::optimize::udp::send_batch(&self.socket, batch_packets)?;
        let total_bytes =
            batch_packets.iter().take(sent_count).map(|(data, _)| data.len()).sum::<usize>();

        self.packets_sent.fetch_add(sent_count as u64, Ordering::Relaxed);
        self.bytes_sent.fetch_add(total_bytes as u64, Ordering::Relaxed);

        Ok(sent_count)
    }

    // Fallback for non-Linux
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        if unlikely(packets.is_empty()) {
            return Ok(0);
        }
        let batch_packets = &packets[..packets.len().min(MAX_BATCH_SIZE)];
        if batch_packets.len() == 1 {
            self.send_single(batch_packets[0].0, batch_packets[0].1)?;
            return Ok(1);
        }
        for window in batch_packets.windows(2) {
            prefetch_outbound_payload(window[1].0.as_ptr());
        }

        let sent_count = crate::optimize::udp::send_batch(&self.socket, batch_packets)?;
        let total_bytes =
            batch_packets.iter().take(sent_count).map(|(data, _)| data.len()).sum::<usize>();

        self.packets_sent.fetch_add(sent_count as u64, Ordering::Relaxed);
        self.bytes_sent.fetch_add(total_bytes as u64, Ordering::Relaxed);

        Ok(sent_count)
    }

    #[cfg(target_os = "windows")]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        let mut sent = 0usize;
        for &(data, addr) in packets {
            self.send_single(data, addr)?;
            sent += 1;
        }
        Ok(sent)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )))]
    pub fn send_batch(&mut self, packets: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        let mut sent = 0;
        for packet in packets {
            self.send_single(packet.0, packet.1)?;
            sent += 1;
        }
        Ok(sent)
    }

    // Single packet send with GSO support
    fn send_single(&mut self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // Prefetch data
        prefetch_outbound_payload(data.as_ptr());

        #[cfg(target_os = "linux")]
        {
            if self.gso_enabled && data.len() > 1400 {
                return self.send_gso(data, addr, 1400);
            }
        }

        let sent = self.socket.send_to(data, addr)?;
        if sent != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("UDP datagram completed with {sent} bytes; expected {}", data.len()),
            ));
        }
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(sent)
    }

    #[cfg(target_os = "linux")]
    fn send_gso(
        &mut self,
        data: &[u8],
        addr: SocketAddr,
        segment_size: usize,
    ) -> io::Result<usize> {
        crate::optimize::udp::validate_datagram_len(data.len())?;
        if segment_size == 0 || segment_size > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid UDP GSO segment size {segment_size}"),
            ));
        }
        let segments =
            data.len().checked_add(segment_size - 1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "UDP GSO size overflow")
            })? / segment_size;

        unsafe {
            let sock_addr = socket2::SockAddr::from(addr);

            let iov = iovec { iov_base: data.as_ptr() as *mut c_void, iov_len: data.len() };

            // Setup control message for GSO
            let cmsg_buf_len = CMSG_SPACE(mem::size_of::<u16>() as u32) as usize;
            let mut cmsg_buf = [0u8; 64];
            if cmsg_buf_len > cmsg_buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP GSO control message exceeds stack buffer",
                ));
            }

            let mut msg: msghdr = mem::zeroed();
            msg.msg_name = sock_addr.as_ptr() as *mut c_void;
            msg.msg_namelen = sock_addr.len();
            msg.msg_iov = &iov as *const _ as *mut iovec;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_buf_len;

            let cmsg = CMSG_FIRSTHDR(&msg);
            if !cmsg.is_null() {
                (*cmsg).cmsg_level = SOL_UDP;
                (*cmsg).cmsg_type = UDP_SEGMENT;
                (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<u16>() as u32) as usize;

                let segment_size_ptr = CMSG_DATA(cmsg) as *mut u16;
                *segment_size_ptr = segment_size as u16;
            }

            let base_flags = MSG_DONTWAIT;
            let sent = libc::sendmsg(self.fd, &msg, base_flags);

            if sent < 0 {
                return Err(io::Error::last_os_error());
            }

            let sent_bytes = usize::try_from(sent).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "UDP GSO returned an invalid byte count")
            })?;
            if sent_bytes != data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!(
                        "UDP GSO datagram completed with {sent_bytes} bytes; expected {}",
                        data.len()
                    ),
                ));
            }
            self.packets_sent.fetch_add(segments as u64, Ordering::Relaxed);
            self.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);

            Ok(sent_bytes)
        }
    }

    // Sophisticated batched receive with recvmmsg on Linux
    #[cfg(target_os = "linux")]
    pub fn recv_batch(&mut self, max_packets: usize) -> io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        unsafe {
            let batch_size = max_packets.min(MAX_BATCH_SIZE);
            if batch_size == 0 {
                return Ok(Vec::new());
            }
            let mut msgs: SmallVec<[mmsghdr; MAX_BATCH_SIZE]> = SmallVec::with_capacity(batch_size);
            let mut iovecs: SmallVec<[iovec; MAX_BATCH_SIZE]> = SmallVec::with_capacity(batch_size);
            let mut addrs: SmallVec<[sockaddr_storage; MAX_BATCH_SIZE]> =
                SmallVec::with_capacity(batch_size);

            for i in 0..batch_size {
                let buf = &mut self.recv_batch[i];

                iovecs.push(iovec {
                    iov_base: buf.as_mut_slice().as_mut_ptr() as *mut c_void,
                    iov_len: buf.as_slice().len(),
                });

                addrs.push(mem::zeroed());

                let mut msg: mmsghdr = mem::zeroed();
                msg.msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut c_void;
                msg.msg_hdr.msg_namelen = mem::size_of::<sockaddr_storage>() as u32;
                msg.msg_hdr.msg_iov = &mut iovecs[i];
                msg.msg_hdr.msg_iovlen = 1;

                msgs.push(msg);
            }

            let mut timeout = timespec {
                tv_sec: 0,
                tv_nsec: 1000000, // 1ms timeout
            };

            let received = recvmmsg(
                self.fd,
                msgs.as_mut_ptr(),
                batch_size as u32,
                MSG_DONTWAIT,
                &mut timeout as *mut _,
            );

            if received < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Ok(Vec::new());
                }
                return Err(err);
            }

            let received_count = crate::optimize::udp::checked_syscall_count(received, batch_size)?;
            let mut results = Vec::with_capacity(received_count);
            let mut total_bytes = 0usize;
            for i in 0..received_count {
                let len = crate::optimize::udp::checked_received_len(
                    msgs[i].msg_len,
                    self.recv_batch[i].as_slice().len(),
                    i,
                )?;
                total_bytes += len;
                let mut data = vec![0u8; len];
                data.copy_from_slice(&self.recv_batch[i].as_slice()[..len]);

                let address_len = usize::try_from(msgs[i].msg_hdr.msg_namelen).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("peer address length at index {i} is not representable"),
                    )
                })?;
                let peer = crate::optimize::udp::socket_addr_from_storage(&addrs[i], address_len)?;
                results.push((data, peer));
            }

            self.packets_received.fetch_add(received_count as u64, Ordering::Relaxed);
            self.bytes_received.fetch_add(total_bytes as u64, Ordering::Relaxed);

            Ok(results)
        }
    }

    // Fallback for non-Linux
    #[cfg(not(target_os = "linux"))]
    pub fn recv_batch(&mut self, max_packets: usize) -> io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        let mut results = Vec::with_capacity(max_packets);
        for _ in 0..max_packets {
            match self.recv_single() {
                Ok(Some((data, addr))) => results.push((data, addr)),
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(results)
    }

    // Single packet receive used by the non-Linux recv_batch fallback.
    #[cfg(not(target_os = "linux"))]
    fn recv_single(&mut self) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        let buf = &mut self.recv_batch[0];
        match self.socket.recv_from(buf.as_mut_slice()) {
            Ok((len, addr)) => {
                let data = buf.as_slice()[..len].to_vec();
                self.packets_received.fetch_add(1, Ordering::Relaxed);
                self.bytes_received.fetch_add(len as u64, Ordering::Relaxed);
                Ok(Some((data, addr)))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn counters_for_rust_tests(&self) -> (u64, u64, u64, u64) {
        (
            self.bytes_sent.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{AlignedBuffer, UdpFastPath};
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    fn send_batch_single_packet_returns_packet_count_not_bytes() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set receiver timeout");
        let recv_addr = receiver.local_addr().expect("receiver addr");

        let mut sender =
            UdpFastPath::new_with_flags("127.0.0.1:0".parse().expect("bind sender"), false, false)
                .expect("create udp fast path");
        let payload = b"single-packet-flush";
        let sent =
            sender.send_batch(&[(payload.as_slice(), recv_addr)]).expect("single packet send");

        assert_eq!(sent, 1, "send_batch reports packets, not bytes");

        let mut buf = [0u8; 128];
        let (n, _) = receiver.recv_from(&mut buf).expect("recv packet");
        assert_eq!(n, payload.len(), "payload length mismatch");
        assert_eq!(&buf[..n], payload, "payload mismatch");

        let (bytes_sent, _, packets_sent, _) = sender.counters_for_rust_tests();
        assert_eq!(bytes_sent, payload.len() as u64);
        assert_eq!(packets_sent, 1);
    }

    #[test]
    fn recv_batch_zero_packets_returns_empty_without_syscall() {
        let mut fast_path =
            UdpFastPath::new_with_flags("127.0.0.1:0".parse().expect("bind addr"), false, false)
                .expect("create udp fast path");

        let packets = fast_path.recv_batch(0).expect("recv zero packet batch");
        assert!(packets.is_empty());

        let (_, bytes_received, _, packets_received) = fast_path.counters_for_rust_tests();
        assert_eq!(bytes_received, 0);
        assert_eq!(packets_received, 0);
    }

    #[test]
    fn aligned_buffer_rejects_size_overflow() {
        assert!(AlignedBuffer::try_new(usize::MAX).is_err());
    }
}
