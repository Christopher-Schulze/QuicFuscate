//! Rust parity/test-only batch shim.
//!
//! This module is not part of the normal runtime transport surface.

#[cfg(any(test, feature = "rust-tests"))]
use qf_cpu::planner::AccelerationPlanner;
#[cfg(any(test, feature = "rust-tests"))]
use qf_transport_udp as accelerate;
#[cfg(any(test, feature = "rust-tests"))]
use std::net::SocketAddr;
#[cfg(any(test, feature = "rust-tests"))]
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicUsize;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(any(test, feature = "rust-tests"))]
use std::time::Duration;

#[cfg(all(unix, not(target_os = "linux"), any(test, feature = "rust-tests")))]
use std::os::unix::io::FromRawFd;

#[cfg(target_os = "linux")]
static BATCH_SENDS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static BATCH_RECVS: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static PACKETS_BATCHED: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(test, feature = "rust-tests"))]
#[allow(dead_code)]
const MAX_UDP_DATAGRAM_SIZE: usize = 65_536;

/// Test/support batch packet processor with network acceleration helpers.
#[cfg(any(test, feature = "rust-tests"))]
#[allow(dead_code)]
pub struct BatchProcessor {
    /// Preallocated buffers for zero-copy batch operations
    recv_buffers: Vec<Vec<u8>>,
    /// IO vectors for sendmmsg/recvmmsg
    #[cfg(target_os = "linux")]
    recv_msgs: Vec<libc::mmsghdr>,
    #[cfg(target_os = "linux")]
    recv_iovecs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    recv_addrs: Vec<libc::sockaddr_storage>,
    /// Batch size based on CPU features
    batch_size: usize,
    #[cfg(feature = "rust-tests")]
    force_batch_send_fallback: bool,
}

#[cfg(any(test, feature = "rust-tests"))]
#[allow(dead_code)]
impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "rust-tests"))]
#[allow(dead_code)]
impl BatchProcessor {
    pub fn new() -> Self {
        let plans = AccelerationPlanner::global();

        // Determine optimal batch size based on CPU
        let batch_size = plans.transport_batch_size();

        log::info!("BatchProcessor: {} packet batches", batch_size);

        // Preallocate buffers
        let mut recv_buffers = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            recv_buffers.push(vec![0u8; MAX_UDP_DATAGRAM_SIZE]);
        }

        #[cfg(target_os = "linux")]
        let recv_msgs = Self::init_mmsg_headers(batch_size);
        #[cfg(target_os = "linux")]
        // SAFETY: `libc::iovec` is a C struct containing only raw pointers and a length.
        // Zero-initializing it is valid because we reinitialize every field before any
        // syscall reads it (see `batch_recv`). All-zeros is a defined C representation
        // for this struct (null pointer + zero length is a no-op iovec).
        let recv_iovecs =
            (0..batch_size).map(|_| unsafe { std::mem::zeroed::<libc::iovec>() }).collect();
        #[cfg(target_os = "linux")]
        // SAFETY: `libc::sockaddr_storage` is a fixed-size opaque buffer used by the
        // kernel to write back the peer address. Zero-initializing it provides a valid
        // starting state; the kernel overwrites the buffer on each successful recvmmsg.
        // The struct contains no types for which zero is an invalid bit pattern.
        let recv_addrs = (0..batch_size)
            .map(|_| unsafe { std::mem::zeroed::<libc::sockaddr_storage>() })
            .collect();

        Self {
            recv_buffers,
            #[cfg(target_os = "linux")]
            recv_msgs,
            #[cfg(target_os = "linux")]
            recv_iovecs,
            #[cfg(target_os = "linux")]
            recv_addrs,
            batch_size,
            #[cfg(feature = "rust-tests")]
            force_batch_send_fallback: false,
        }
    }

    #[cfg(feature = "rust-tests")]
    pub fn force_batch_send_fallback(&mut self, force: bool) {
        self.force_batch_send_fallback = force;
    }

    #[cfg(target_os = "linux")]
    fn init_mmsg_headers(batch_size: usize) -> Vec<libc::mmsghdr> {
        let mut recv_msgs = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            // SAFETY: `libc::mmsghdr` is a C struct whose fields are all reinitialized in
            // `batch_recv` before the kernel reads them. Zero-initializing provides a safe
            // scratch state; the struct contains no Rust types that require non-zero init.
            recv_msgs.push(unsafe { std::mem::zeroed() });
        }

        recv_msgs
    }

    /// Best-effort socket capability setup for batch transport paths.
    ///
    /// This preserves the public API used by tests/integration while avoiding
    /// hidden state in `BatchProcessor`. Socket-level options are applied
    /// directly to the provided descriptor when supported by the OS/kernel.
    pub fn init_acceleration(&mut self, socket: &UdpSocket) -> std::io::Result<()> {
        let gso_enabled = qf_transport_udp::UdpGsoConfig::enable(socket)
            .map(|config| config.enabled)
            .unwrap_or(false);
        log::info!("Network acceleration initialized:");
        log::info!("  GSO: {}", gso_enabled);
        Ok(())
    }

    /// Batch send packets with sendmmsg and acceleration (Linux).
    ///
    /// A successful return is the number of complete datagrams. A nonblocking
    /// error after a completed prefix returns that prefix count; an error before
    /// progress is returned as an `io::Error`. A short datagram result is always
    /// a typed `WriteZero` error and is never counted as complete.
    #[cfg(target_os = "linux")]
    pub fn batch_send(
        &mut self,
        socket: i32,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        // Try accelerated batch send first
        #[cfg(not(feature = "rust-tests"))]
        {
            let result = accelerate::send_batch_fd(socket, packets);

            match result {
                Ok(sent) => {
                    BATCH_SENDS.fetch_add(1, Ordering::Relaxed);
                    PACKETS_BATCHED.fetch_add(sent, Ordering::Relaxed);
                    return Ok(sent);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::InvalidData | std::io::ErrorKind::WriteZero
                    ) =>
                {
                    return Err(error)
                }
                Err(_) => {}
            }
        }

        #[cfg(feature = "rust-tests")]
        if !self.force_batch_send_fallback {
            let result = accelerate::send_batch_fd(socket, packets);

            match result {
                Ok(sent) => {
                    BATCH_SENDS.fetch_add(1, Ordering::Relaxed);
                    PACKETS_BATCHED.fetch_add(sent, Ordering::Relaxed);
                    return Ok(sent);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::InvalidData | std::io::ErrorKind::WriteZero
                    ) =>
                {
                    return Err(error)
                }
                Err(_) => {}
            }
        }

        // Conservative fallback: per-packet send_to without payload rewriting/truncation.
        // This avoids silent truncation for payloads larger than preallocated scratch buffers.
        let batch_count = packets.len();
        if batch_count == 0 {
            return Ok(0);
        }

        let mut sent = 0usize;
        'send_loop: for (data, addr) in packets.iter().take(batch_count) {
            qf_transport_udp::validate_datagram_len(data.len())?;
            let sock_addr = socket2::SockAddr::from(*addr);
            loop {
                // SAFETY: `socket` is a valid UDP fd supplied by the caller. `data` and
                // `sock_addr` live for the duration of this syscall and are not retained.
                let rc = unsafe {
                    libc::sendto(
                        socket,
                        data.as_ptr() as *const libc::c_void,
                        data.len(),
                        libc::MSG_DONTWAIT,
                        sock_addr.as_ptr(),
                        sock_addr.len(),
                    )
                };
                if rc >= 0 {
                    let bytes = usize::try_from(rc).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "sendto returned an unrepresentable byte count",
                        )
                    })?;
                    if bytes != data.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            format!(
                                "UDP datagram completed with {bytes} bytes; expected {}",
                                data.len()
                            ),
                        ));
                    }
                    sent += 1;
                    break;
                }

                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::Interrupted => continue,
                    std::io::ErrorKind::WouldBlock => {
                        if sent == 0 {
                            return Err(err);
                        }
                        break 'send_loop;
                    }
                    _ => {
                        if sent > 0 {
                            break 'send_loop;
                        }
                        return Err(err);
                    }
                }
            }
        }

        BATCH_SENDS.fetch_add(1, Ordering::Relaxed);
        PACKETS_BATCHED.fetch_add(sent, Ordering::Relaxed);

        Ok(sent)
    }

    /// Batch receive packets with recvmmsg (Linux)
    #[cfg(target_os = "linux")]
    pub fn batch_recv(
        &mut self,
        socket: i32,
        timeout: Option<Duration>,
    ) -> std::io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        use std::mem;

        let mut results = Vec::with_capacity(self.batch_size);

        // Setup timeout
        let mut ts = timeout
            .map(|d| {
                let tv_sec = libc::time_t::try_from(d.as_secs()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "UDP receive timeout exceeds the platform time_t range",
                    )
                })?;
                let tv_nsec = libc::c_long::try_from(d.subsec_nanos()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "UDP receive timeout nanoseconds exceed the platform range",
                    )
                })?;
                Ok(libc::timespec { tv_sec, tv_nsec })
            })
            .transpose()?;

        let batch_count = u32::try_from(self.batch_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP receive batch size exceeds the syscall count width",
            )
        })?;

        // Setup receive messages
        for i in 0..self.batch_size {
            // SAFETY: `sockaddr_storage` is an opaque C buffer; zero is a valid bit
            // pattern for it. We reset it here before each batch so stale address data
            // from a previous call cannot leak into the current receive results.
            self.recv_addrs[i] = unsafe { mem::zeroed() };
            self.recv_iovecs[i] = libc::iovec {
                iov_base: self.recv_buffers[i].as_mut_ptr() as *mut _,
                iov_len: self.recv_buffers[i].len(),
            };

            self.recv_msgs[i] = libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut self.recv_addrs[i] as *mut _ as *mut _,
                    msg_namelen: mem::size_of::<libc::sockaddr_storage>() as u32,
                    msg_iov: &mut self.recv_iovecs[i] as *mut libc::iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
        }

        // Receive all packets in one syscall!
        // SAFETY: All preconditions for recvmmsg are satisfied:
        // - `socket` is a valid open UDP socket fd supplied by the caller.
        // - `recv_msgs` has `batch_size` initialized entries, each with `msg_iov` pointing
        //   into `recv_iovecs` and `msg_name` pointing into `recv_addrs` - both live for
        //   the duration of this call.
        // - Each `iov_base` in `recv_iovecs` points to a uniquely-owned `Vec<u8>` buffer
        //   of length `MAX_UDP_DATAGRAM_SIZE`; no aliasing exists between buffers.
        // - The timeout pointer, if non-null, points to a valid `libc::timespec` on the
        //   stack above. We pass null when no timeout is requested.
        let received = unsafe {
            libc::recvmmsg(
                socket,
                self.recv_msgs.as_mut_ptr(),
                batch_count,
                libc::MSG_DONTWAIT,
                ts.as_mut().map_or(std::ptr::null_mut(), |t| t as *mut _),
            )
        };

        if received < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(results);
            }
            return Err(err);
        }

        let received_count = qf_transport_udp::checked_syscall_count(received, self.batch_size)?;

        // Process received packets. Zero-length UDP datagrams are valid and are
        // preserved; malformed kernel metadata is an error, never a skipped packet.
        for i in 0..received_count {
            let len = qf_transport_udp::checked_received_len(
                self.recv_msgs[i].msg_len,
                self.recv_buffers[i].len(),
                i,
            )?;
            let mut data = vec![0u8; len];
            data.copy_from_slice(&self.recv_buffers[i][..len]);
            let address_len =
                usize::try_from(self.recv_msgs[i].msg_hdr.msg_namelen).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("peer address length at index {i} is not representable"),
                    )
                })?;
            let addr =
                qf_transport_udp::socket_addr_from_storage(&self.recv_addrs[i], address_len)?;
            results.push((data, addr));
        }

        BATCH_RECVS.fetch_add(1, Ordering::Relaxed);
        PACKETS_BATCHED.fetch_add(received_count, Ordering::Relaxed);
        qf_telemetry::ZERO_COPY_RECVS.inc_by(received_count as u64);

        Ok(results)
    }

    /// Batched send for macOS/iOS using sendmsg_x (best-effort).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn batch_send(
        &mut self,
        socket: i32,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        // SAFETY: `socket` is a valid, open UDP socket fd provided by the caller.
        // ManuallyDrop prevents this temporary view from closing the caller-owned
        // descriptor on either success or an early send error.
        let sock = std::mem::ManuallyDrop::new(unsafe { UdpSocket::from_raw_fd(socket) });
        let result = accelerate::send_batch(&sock, packets);

        match result {
            Ok(sent) => {
                qf_telemetry::ZERO_COPY_SENDS.inc_by(sent as u64);
                Ok(sent)
            }
            Err(err) => Err(err),
        }
    }

    /// Fallback for non-Linux, non-Apple Unix systems
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos", target_os = "ios"))))]
    pub fn batch_send(
        &mut self,
        socket: i32,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        // SAFETY: `socket` is a valid, open UDP socket fd provided by the caller.
        // ManuallyDrop prevents this temporary view from closing the caller-owned
        // descriptor when a send fails before the loop completes.
        let sock = std::mem::ManuallyDrop::new(unsafe { UdpSocket::from_raw_fd(socket) });
        let mut sent = 0usize;
        for (data, addr) in packets {
            let bytes = sock.send_to(data, addr)?;
            if bytes != data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!("UDP datagram completed with {bytes} bytes; expected {}", data.len()),
                ));
            }
            sent += 1;
        }
        Ok(sent)
    }

    /// Fallback for Windows systems
    #[cfg(target_os = "windows")]
    pub fn batch_send(
        &mut self,
        socket: std::os::windows::io::RawSocket,
        packets: &[(&[u8], SocketAddr)],
    ) -> std::io::Result<usize> {
        use std::os::windows::io::FromRawSocket;
        // SAFETY: `socket` is a valid, open RawSocket provided by the caller.
        // ManuallyDrop prevents the temporary UdpSocket view from closing the
        // caller-owned handle on either success or an early send error.
        let sock = std::mem::ManuallyDrop::new(unsafe { UdpSocket::from_raw_socket(socket) });
        let mut sent = 0usize;
        for (data, addr) in packets {
            let bytes = sock.send_to(data, addr)?;
            if bytes != data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    format!("UDP datagram completed with {bytes} bytes; expected {}", data.len()),
                ));
            }
            sent += 1;
        }
        Ok(sent)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn batch_recv(
        &mut self,
        _socket: i32,
        _timeout: Option<Duration>,
    ) -> std::io::Result<Vec<(Vec<u8>, SocketAddr)>> {
        // Fallback to individual receives
        log::debug!("Batch recv not available on this platform");
        let _ = (self.recv_buffers.len(), self.batch_size);
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_processor_construction() {
        let bp = BatchProcessor::new();
        assert!(bp.batch_size > 0, "batch_size must be positive");
        assert_eq!(bp.recv_buffers.len(), bp.batch_size);
        for buf in &bp.recv_buffers {
            assert_eq!(buf.len(), MAX_UDP_DATAGRAM_SIZE);
        }
    }

    #[test]
    fn test_batch_processor_default() {
        let bp = BatchProcessor::default();
        assert!(bp.batch_size > 0);
        assert_eq!(bp.recv_buffers.len(), bp.batch_size);
    }

    #[test]
    fn test_batch_processor_recv_buffers_preallocated() {
        let bp = BatchProcessor::new();
        // Every buffer should be exactly MAX_UDP_DATAGRAM_SIZE and zeroed
        for buf in &bp.recv_buffers {
            assert_eq!(buf.len(), MAX_UDP_DATAGRAM_SIZE);
            assert!(buf.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn test_batch_processor_batch_size_positive() {
        // AccelerationPlanner should always yield a reasonable batch size
        let plans = AccelerationPlanner::global();
        let size = plans.transport_batch_size();
        assert!(size >= 1, "transport_batch_size must be >= 1, got {size}");
        assert!(size <= 1024, "transport_batch_size should be reasonable, got {size}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_batch_processor_linux_mmsg_headers() {
        let bp = BatchProcessor::new();
        assert_eq!(bp.recv_msgs.len(), bp.batch_size);
        assert_eq!(bp.recv_iovecs.len(), bp.batch_size);
        assert_eq!(bp.recv_addrs.len(), bp.batch_size);
    }

    #[test]
    fn test_non_linux_batch_recv_returns_empty() {
        // On non-Linux, batch_recv is a no-op that returns empty Vec
        #[cfg(not(target_os = "linux"))]
        {
            let mut bp = BatchProcessor::new();
            let result = bp.batch_recv(-1, Some(Duration::from_millis(10)));
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }
    }

    #[test]
    fn test_init_acceleration_with_real_socket() {
        // Bind a real UDP socket and verify init_acceleration does not panic
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
        let mut bp = BatchProcessor::new();
        // init_acceleration may fail on some platforms but should not panic
        let _ = bp.init_acceleration(&socket);
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_batch_send_preserves_caller_socket_after_error() {
        use std::os::unix::io::AsRawFd;

        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set receiver timeout");
        let destination = receiver.local_addr().expect("receiver address");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let oversized_payload = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        let oversized_packets = [(oversized_payload.as_slice(), destination)];
        let mut batch = BatchProcessor::new();

        batch
            .batch_send(sender.as_raw_fd(), &oversized_packets)
            .expect_err("oversized UDP payload must fail");
        assert!(sender.local_addr().is_ok(), "batch send closed the caller socket");

        let recovery_payload = b"after-send-error";
        let recovery_packets = [(recovery_payload.as_slice(), destination)];
        assert_eq!(
            batch.batch_send(sender.as_raw_fd(), &recovery_packets).expect("recovery send"),
            1
        );
        let mut receive_buffer = [0u8; 64];
        let (recovery_len, _) = receiver.recv_from(&mut receive_buffer).expect("receive recovery");
        assert_eq!(&receive_buffer[..recovery_len], recovery_payload);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_batch_send_rejects_invalid_caller_fd() {
        let destination: SocketAddr = "127.0.0.1:9".parse().expect("destination");
        let payload = b"invalid-fd";
        let mut batch = BatchProcessor::new();

        let error = batch
            .batch_send(-1, &[(payload.as_slice(), destination)])
            .expect_err("invalid caller fd must fail");
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_batch_send_preserves_destinations_and_socket_ownership() {
        use std::os::windows::io::AsRawSocket;

        let first_receiver = UdpSocket::bind("127.0.0.1:0").expect("bind first receiver");
        let second_receiver = UdpSocket::bind("127.0.0.1:0").expect("bind second receiver");
        first_receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set first receiver timeout");
        second_receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set second receiver timeout");

        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let first_payload = b"first-destination";
        let second_payload = b"second-destination";
        let packets = [
            (
                first_payload.as_slice(),
                first_receiver.local_addr().expect("first receiver address"),
            ),
            (
                second_payload.as_slice(),
                second_receiver.local_addr().expect("second receiver address"),
            ),
        ];

        let mut batch = BatchProcessor::new();
        let sent = batch.batch_send(sender.as_raw_socket(), &packets).expect("batch send");
        assert_eq!(sent, packets.len());

        let mut receive_buffer = [0u8; 64];
        let (first_len, _) =
            first_receiver.recv_from(&mut receive_buffer).expect("receive first payload");
        assert_eq!(&receive_buffer[..first_len], first_payload);
        let (second_len, _) =
            second_receiver.recv_from(&mut receive_buffer).expect("receive second payload");
        assert_eq!(&receive_buffer[..second_len], second_payload);

        let oversized_payload = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
        let oversized_packets = [(oversized_payload.as_slice(), packets[0].1)];
        batch
            .batch_send(sender.as_raw_socket(), &oversized_packets)
            .expect_err("oversized UDP payload must fail");
        assert!(sender.local_addr().is_ok(), "batch send closed the caller-owned socket");

        let recovery_payload = b"after-send-error";
        let recovery_packets = [(recovery_payload.as_slice(), packets[0].1)];
        assert_eq!(
            batch.batch_send(sender.as_raw_socket(), &recovery_packets).expect("recovery send"),
            1
        );
        let (recovery_len, _) =
            first_receiver.recv_from(&mut receive_buffer).expect("receive recovery payload");
        assert_eq!(&receive_buffer[..recovery_len], recovery_payload);
    }
}
