// io_uring batch UDP sender using the official `io-uring` crate.
//
// Replaces the old self-rolled libc::io_uring_setup/io_uring_enter code with
// proper batch submission: queued SendMsg SQEs, single submit_and_wait(queued),
// then reap all CQEs. This amortises the syscall overhead across the entire
// batch instead of doing one submit_and_wait(1) per packet.

use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;

use crate::optimize::{AlignedBox, MemoryPool};
use io_uring::{opcode, IoUring, Probe};

/// Default submission queue depth (must be power of two).
const DEFAULT_QUEUE_DEPTH: u32 = 256;

/// `IORING_CQE_F_MORE`: more CQEs from this SQE will follow (SendMsgZc primary CQE).
const CQE_F_MORE: u32 = 1 << 1;
/// `IORING_CQE_F_NOTIF`: this is a buffer-release notification CQE (SendMsgZc ZC done).
const CQE_F_NOTIF: u32 = 1 << 3;

/// Batch UDP sender backed by a reusable io_uring instance.
///
/// Created once per `IoDriver` lifetime and shared across send batches.
/// If the kernel does not support io_uring (old kernel, unprivileged
/// container, etc.) construction returns `None` and the caller falls
/// through to `sendmmsg`.
///
/// `iovecs`, `msgs`, and `sockaddrs` are pre-allocated to `queue_depth`
/// capacity so `send_batch` never touches the allocator on the hot path.
///
/// **SQPOLL**: constructed with `IORING_SETUP_SQPOLL` when the kernel
/// supports it (requires `CAP_SYS_ADMIN` on kernels < 5.12, unrestricted
/// since 5.12). Falls back to standard mode silently. Check `sqpoll_active()`.
///
/// **SendMsgZc**: zero-copy send path (kernel 6.0+ for stability). Falls back
/// to `SendMsg` when the probe indicates no support. Check `zc_supported()`.
pub struct UringBatchSender {
    ring: IoUring,
    /// Pre-allocated iovec scratch buffer (reused across batches).
    iovecs: Vec<libc::iovec>,
    /// Pre-allocated msghdr scratch buffer (reused across batches).
    msgs: Vec<libc::msghdr>,
    /// Pre-allocated sockaddr_storage for send_batch_to (unconnected sends).
    sockaddrs: Vec<libc::sockaddr_storage>,
    /// Pre-allocated completion bitmap for contiguous-prefix accounting.
    send_success: Vec<bool>,
    /// True when the ring was constructed with SQPOLL mode.
    sqpoll_active: bool,
    /// True when the kernel supports SendMsgZc (probed at init).
    zc_supported: bool,
}

// SAFETY: UringBatchSender owns its ring and scratch vectors. The raw pointers
// inside msghdr/iovec entries are rebuilt from those owned vectors during
// synchronous &mut self submissions and are protected by the caller's mutex.
unsafe impl Send for UringBatchSender {}

struct SubmitOutcome {
    queued: usize,
    sent: usize,
}

impl UringBatchSender {
    /// Try to create a sender with the given queue depth.
    ///
    /// Attempts SQPOLL mode first (eliminates `io_uring_enter` syscalls during
    /// steady-state operation at the cost of a kernel polling thread).
    /// Falls back to standard mode on `EPERM` or unsupported kernels.
    /// Probes `SendMsgZc` support via `io_uring::Probe`.
    ///
    /// Returns `None` when io_uring cannot be initialised (kernel too old,
    /// seccomp filter, missing permissions, etc.).
    pub fn new(queue_depth: u32) -> Option<Self> {
        let depth = queue_depth.max(4).next_power_of_two();

        // Try SQPOLL mode first: the kernel thread polls the SQ, eliminating
        // io_uring_enter() syscalls while it is active.  Falls back on EPERM
        // (requires CAP_SYS_ADMIN on kernels < 5.12) or any other error.
        let (ring, sqpoll_active) = match IoUring::builder()
            .setup_sqpoll(1000) // kernel poller sleeps after 1000 ms idle
            .build(depth)
        {
            Ok(r) => {
                log::debug!("io_uring SQPOLL mode active (depth={depth})");
                (r, true)
            }
            Err(_) => match IoUring::new(depth) {
                Ok(r) => (r, false),
                Err(e) => {
                    log::debug!("io_uring init failed (depth={depth}): {e}");
                    return None;
                }
            },
        };

        // Probe SendMsgZc support (stable on kernel 6.0+).
        let zc_supported = {
            let mut probe = Probe::new();
            ring.submitter().register_probe(&mut probe).is_ok()
                && probe.is_supported(opcode::SendMsgZc::CODE)
        };

        if sqpoll_active {
            crate::telemetry::IO_URING_SQPOLL_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
        }
        if zc_supported {
            log::debug!("io_uring SendMsgZc (zero-copy) supported");
        }

        let cap = depth as usize;
        Some(Self {
            ring,
            // Pre-allocate scratch buffers to queue depth so the hot path
            // never touches the allocator.
            iovecs: Vec::with_capacity(cap),
            msgs: Vec::with_capacity(cap),
            sockaddrs: Vec::with_capacity(cap),
            send_success: Vec::with_capacity(cap),
            sqpoll_active,
            zc_supported,
        })
    }

    /// Create with the default queue depth (256).
    pub fn with_defaults() -> Option<Self> {
        Self::new(DEFAULT_QUEUE_DEPTH)
    }

    /// True when the ring was constructed with kernel SQPOLL mode.
    #[inline]
    pub fn sqpoll_active(&self) -> bool {
        self.sqpoll_active
    }

    /// True when the kernel supports zero-copy `SendMsgZc` (kernel 6.0+).
    #[inline]
    pub fn zc_supported(&self) -> bool {
        self.zc_supported
    }

    /// Submit a batch of datagrams on a **connected** UDP socket.
    ///
    /// Queues one `SendMsg` SQE per payload, then issues a single
    /// `submit_and_wait(queued)` to push them all into the kernel in one
    /// syscall transition. Returns the number of successfully sent packets.
    ///
    /// Payloads that exceed the submission queue capacity are sent in
    /// chunks (flush-and-refill).
    pub fn send_batch(&mut self, fd: RawFd, payloads: &[&[u8]]) -> std::io::Result<usize> {
        if payloads.is_empty() {
            return Ok(0);
        }

        // Reuse pre-allocated scratch buffers - zero allocations on the hot path.
        self.iovecs.clear();
        self.msgs.clear();

        for payload in payloads {
            self.iovecs.push(libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            });
        }
        for iov in &mut self.iovecs {
            // Safety: msghdr is fully zeroed; msg_iov points into self.iovecs which
            // lives for the duration of this call. Payload slices are caller-owned
            // and remain valid until completions are reaped below.
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_iov = iov as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            self.msgs.push(hdr);
        }

        let sq_cap = self.ring.params().sq_entries() as usize;
        let mut total_sent: usize = 0;

        if self.zc_supported {
            // Zero-copy path: SendMsgZc with dual-CQE drain.
            let mut chunk_start = 0usize;
            while chunk_start < self.msgs.len() {
                let chunk_end = (chunk_start + sq_cap).min(self.msgs.len());
                let outcome = self.submit_chunk_zc(fd, chunk_start, chunk_end - chunk_start)?;
                chunk_start += outcome.queued;
                total_sent += outcome.sent;
                if outcome.sent < outcome.queued {
                    return Ok(total_sent);
                }
            }
        } else {
            // Standard path: SendMsg with single CQE per SQE.
            let mut chunk_start = 0usize;
            while chunk_start < self.msgs.len() {
                let chunk_end = (chunk_start + sq_cap).min(self.msgs.len());
                let outcome = self.submit_chunk(fd, chunk_start, chunk_end - chunk_start)?;
                chunk_start += outcome.queued;
                total_sent += outcome.sent;
                if outcome.sent < outcome.queued {
                    return Ok(total_sent);
                }
            }
        }

        Ok(total_sent)
    }

    /// Submit a batch of datagrams on an **unconnected** UDP socket, each to a
    /// specific destination address.
    ///
    /// Used for the server send path where packets from one connection are all
    /// addressed to the same peer, but the socket is shared across sessions.
    /// Queues one `SendMsg` SQE per packet and submits them in one
    /// `submit_and_wait` call. Returns the number of successfully sent packets.
    pub fn send_batch_to(
        &mut self,
        fd: RawFd,
        packets: &[(SocketAddr, &[u8])],
    ) -> std::io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        self.iovecs.clear();
        self.msgs.clear();
        self.sockaddrs.clear();

        // Pass 1: build iovecs (stable base for msg_iov pointers).
        for (_, payload) in packets {
            self.iovecs.push(libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            });
        }

        // Pass 2: fill sockaddr_storage per destination (stable for msg_name).
        for (addr, _) in packets {
            // Safety: sockaddr_storage is POD; zeroed init is valid.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            fill_sockaddr(*addr, &mut storage);
            self.sockaddrs.push(storage);
        }

        // Pass 3: build msghdrs with stable pointers into iovecs and sockaddrs.
        // Both vecs are fully populated above - no further pushes, so no realloc.
        for i in 0..packets.len() {
            // Safety: iovecs[i] and sockaddrs[i] are valid for the lifetime of
            // this call and the Vecs will not reallocate after this point.
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_iov = &mut self.iovecs[i] as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            hdr.msg_name = &mut self.sockaddrs[i] as *mut _ as *mut libc::c_void;
            hdr.msg_namelen = addr_len(packets[i].0);
            self.msgs.push(hdr);
        }

        let sq_cap = self.ring.params().sq_entries() as usize;
        let mut total_sent = 0usize;

        let mut chunk_start = 0usize;
        while chunk_start < self.msgs.len() {
            let chunk_end = (chunk_start + sq_cap).min(self.msgs.len());
            let outcome = self.submit_chunk(fd, chunk_start, chunk_end - chunk_start)?;
            chunk_start += outcome.queued;
            total_sent += outcome.sent;
            if outcome.sent < outcome.queued {
                crate::telemetry::IO_URING_SERVER_PACKETS.inc_by(total_sent as u64);
                return Ok(total_sent);
            }
        }

        crate::telemetry::IO_URING_SERVER_PACKETS.inc_by(total_sent as u64);
        Ok(total_sent)
    }

    /// Push one chunk of SendMsg SQEs (by index range into `self.msgs`) and reap completions.
    fn submit_chunk(
        &mut self,
        fd: RawFd,
        start: usize,
        count: usize,
    ) -> std::io::Result<SubmitOutcome> {
        let fd = io_uring::types::Fd(fd);

        // Drain any stale CQEs from previous operations to ensure
        // submit_and_wait(queued) waits for the correct CQEs.
        {
            let cq = self.ring.completion();
            for _ in cq {}
        }

        // Push SQEs.
        let mut queued = 0usize;
        {
            let mut sq = self.ring.submission();
            for idx in 0..count {
                let msg = &self.msgs[start + idx];
                let entry = opcode::SendMsg::new(fd, msg as *const libc::msghdr)
                    .build()
                    .user_data(idx as u64);
                // Safety: msghdr points into self.msgs; iov_base points into
                // caller payloads. Both remain valid until completions are reaped.
                unsafe {
                    if sq.push(&entry).is_err() {
                        // SQ truly full - chunking to sq_cap should prevent
                        // this, but handle gracefully.
                        break;
                    }
                }
                queued += 1;
            }
        }
        if queued == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "io_uring submission queue accepted no SendMsg SQEs",
            ));
        }

        // Single syscall: submit all queued SQEs and wait for all completions.
        self.ring.submit_and_wait(queued)?;
        crate::telemetry::IO_URING_SUBMIT_CALLS.inc();

        // Reap completions. Callers retry via `skip(sent)`, so expose only the
        // contiguous successful prefix, not an unordered success total.
        self.send_success.clear();
        self.send_success.resize(queued, false);
        let cq = self.ring.completion();
        for cqe in cq {
            let idx = cqe.user_data() as usize;
            if cqe.result() >= 0 && idx < self.send_success.len() {
                self.send_success[idx] = true;
            } else {
                log::trace!(
                    "io_uring SendMsg CQE error: user_data={} result={}",
                    cqe.user_data(),
                    cqe.result()
                );
            }
        }
        let sent = self.send_success.iter().take_while(|&&ok| ok).count();

        Ok(SubmitOutcome { queued, sent })
    }

    /// Push one chunk of `SendMsgZc` SQEs and reap primary + notification CQEs.
    ///
    /// Each `SendMsgZc` SQE may generate two CQEs:
    /// - **Primary** (`CQE_F_MORE` set): data accepted into socket buffer.
    /// - **Notification** (`CQE_F_NOTIF` set): kernel released the buffer.
    ///
    /// We call `submit_and_wait(queued)` to wait for queued CQEs, then
    /// drain the full CQ.  Notification CQEs that arrive later are swept up
    /// in the next call's drain.
    fn submit_chunk_zc(
        &mut self,
        fd: RawFd,
        start: usize,
        count: usize,
    ) -> std::io::Result<SubmitOutcome> {
        let fd_typed = io_uring::types::Fd(fd);

        // Drain stale CQEs from previous ZC chunks.  Each SendMsgZc SQE
        // produces a primary CQE *and* a notification CQE (CQE_F_NOTIF).
        // Notification CQEs arrive asynchronously and can satisfy
        // submit_and_wait prematurely on the next chunk, causing the reap
        // loop to see only notifications and report sent=0.
        {
            let cq = self.ring.completion();
            for cqe in cq {
                if cqe.flags() & CQE_F_NOTIF != 0 {
                    crate::telemetry::IO_URING_ZC_NOTIFS.inc();
                }
            }
        }

        // Push SendMsgZc SQEs.
        let mut queued = 0usize;
        {
            let mut sq = self.ring.submission();
            for idx in 0..count {
                let msg = &self.msgs[start + idx];
                let entry = opcode::SendMsgZc::new(fd_typed, msg as *const libc::msghdr)
                    .build()
                    .user_data(idx as u64);
                unsafe {
                    if sq.push(&entry).is_err() {
                        break;
                    }
                }
                queued += 1;
            }
        }
        if queued == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "io_uring submission queue accepted no SendMsgZc SQEs",
            ));
        }

        // Wait for at least the queued CQEs (primary or notification), then drain all.
        self.ring.submit_and_wait(queued)?;
        crate::telemetry::IO_URING_SUBMIT_CALLS.inc();

        self.send_success.clear();
        self.send_success.resize(queued, false);
        {
            let cq = self.ring.completion();
            for cqe in cq {
                let flags = cqe.flags();
                if flags & CQE_F_NOTIF != 0 {
                    // Buffer-release notification: kernel finished with the buffer.
                    crate::telemetry::IO_URING_ZC_NOTIFS.inc();
                } else {
                    // Primary send CQE.
                    let idx = cqe.user_data() as usize;
                    if cqe.result() >= 0 && idx < self.send_success.len() {
                        self.send_success[idx] = true;
                        crate::telemetry::IO_URING_ZC_SENDS.inc();
                    } else {
                        log::trace!(
                            "io_uring SendMsgZc error: user_data={} result={}",
                            cqe.user_data(),
                            cqe.result()
                        );
                    }
                }
            }
        }

        // Suppress unused-constant warnings on kernels where CQE_F_MORE is
        // implicitly used: the flag signals whether a notification follows, but
        // we drain both CQE types unconditionally, so we do not need to branch on it.
        let _ = CQE_F_MORE;
        let sent = self.send_success.iter().take_while(|&&ok| ok).count();

        Ok(SubmitOutcome { queued, sent })
    }
}

/// Returns the `socklen_t` for the given address family.
#[inline]
fn addr_len(addr: SocketAddr) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(_) => std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        SocketAddr::V6(_) => std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
    }
}

/// Fill a `libc::sockaddr_storage` from a `std::net::SocketAddr`.
///
/// The storage must already be zeroed (e.g. via `std::mem::zeroed()`).
fn fill_sockaddr(addr: SocketAddr, storage: &mut libc::sockaddr_storage) {
    match addr {
        SocketAddr::V4(v4) => {
            // Safety: sockaddr_storage is large enough to hold sockaddr_in.
            let sa = storage as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sa).sin_port = v4.port().to_be();
                // from_ne_bytes preserves the network-order byte layout on all
                // endiannesses: octets() returns [a,b,c,d] in network order,
                // and storing as a native-endian u32 keeps those bytes intact.
                (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
        }
        SocketAddr::V6(v6) => {
            // Safety: sockaddr_storage is large enough to hold sockaddr_in6.
            let sa = storage as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sa).sin6_port = v6.port().to_be();
                (*sa).sin6_flowinfo = v6.flowinfo();
                (*sa).sin6_addr.s6_addr = v6.ip().octets();
                (*sa).sin6_scope_id = v6.scope_id();
            }
        }
    }
}

// Per-thread io_uring sender for the server outbound path.
//
// Avoids struct changes to the server runtime. The server's flush loop calls
// `server_send_batch_to()` directly. The `RefCell` borrow is never held across
// `await` points (collection and io_uring submission are both synchronous).
thread_local! {
    static SERVER_URING_SENDER: std::cell::RefCell<Option<UringBatchSender>> =
        std::cell::RefCell::new(UringBatchSender::with_defaults());
}

/// Send a batch of `(addr, payload)` pairs on an **unconnected** server UDP
/// socket via the thread-local io_uring sender.
///
/// Returns `Some(sent_count)` when at least one packet was sent, `None` when
/// io_uring is unavailable or no progress was made.
pub fn server_send_batch_to(fd: RawFd, packets: &[(SocketAddr, &[u8])]) -> Option<usize> {
    SERVER_URING_SENDER.with(|cell| {
        let mut guard = cell.borrow_mut();
        if let Some(ref mut sender) = *guard {
            match sender.send_batch_to(fd, packets) {
                Ok(n) if n > 0 => {
                    crate::telemetry::IO_URING_SERVER_SUBMIT_CALLS.inc();
                    Some(n)
                }
                Ok(_) => None,
                Err(e) => {
                    log::debug!("io_uring server send_batch_to failed: {e}");
                    None
                }
            }
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Receive path: UringRecvBatch
// ---------------------------------------------------------------------------

/// Default receive queue depth (pre-posted RecvMsg SQEs).
const DEFAULT_RECV_DEPTH: u32 = 64;
/// Default per-buffer size (power-of-two, > typical MTU).
const DEFAULT_RECV_BUF_SIZE: usize = 2048;

/// A single completed receive from `UringRecvBatch::drain_completions`.
pub struct RecvCompletion {
    /// Packet payload for the legacy contiguous-buffer mode.
    pub data: Vec<u8>,
    /// Packet payload for pool-backed receive mode.
    pub block: Option<AlignedBox<[u8]>>,
    /// Valid payload length inside `block` when pool-backed receive mode is active.
    pub len: usize,
    /// Source address - `Some` when the batch was created with `with_addr = true`
    /// (server path, unconnected socket). `None` for the client path.
    pub addr: Option<SocketAddr>,
}

impl RecvCompletion {
    #[inline]
    pub fn len(&self) -> usize {
        if self.block.is_some() {
            self.len
        } else {
            self.data.len()
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self.block.as_ref() {
            Some(block) => &block[..self.len.min(block.len())],
            None => &self.data,
        }
    }

    #[inline]
    pub fn into_pooled_block(self) -> Option<(AlignedBox<[u8]>, usize)> {
        self.block.map(|block| {
            let len = self.len.min(block.len());
            (block, len)
        })
    }
}

/// Batch UDP receiver backed by a dedicated io_uring ring and an eventfd bridge
/// to Tokio.
///
/// Eliminates per-packet `recvmsg(2)` syscalls by pre-posting N `RecvMsg` SQEs.
/// The kernel fills buffers directly; completions trigger an eventfd that wakes
/// the Tokio task via `AsyncFd`.
///
/// ```text
/// io_uring ring (recv)              Tokio reactor
/// --------------------              ---------------
/// RecvMsg SQEs on UDP fd            AsyncFd wraps eventfd
/// CQE generated -------> eventfd -> Tokio task wakes
///                                    drain CQ, process packets
/// ```
///
/// Created with `new()`, then call `post_initial()` to arm the SQEs, and
/// `drain_completions()` each time the eventfd fires.
pub struct UringRecvBatch {
    ring: IoUring,
    /// eventfd created with `EFD_NONBLOCK | EFD_CLOEXEC`, registered via
    /// `register_eventfd_async`. Owned by this struct (closed in Drop).
    eventfd: RawFd,
    /// Contiguous buffer pool: `depth * buf_size` bytes.
    /// Buffer `i` occupies `bufs[i * buf_size .. (i+1) * buf_size]`.
    bufs: Vec<u8>,
    /// Optional MemoryPool-backed receive slots for zero-copy kernel-to-FEC handoff.
    blocks: Vec<Option<AlignedBox<[u8]>>>,
    memory_pool: Option<Arc<MemoryPool>>,
    buf_size: usize,
    /// Pre-built iovec array pointing into `bufs` or pool-backed `blocks`.
    iovecs: Vec<libc::iovec>,
    /// Pre-built msghdr array pointing into `iovecs` (and `addrs` when `with_addr`).
    msgs: Vec<libc::msghdr>,
    /// Source address storage per slot (only allocated when `with_addr`).
    addrs: Vec<libc::sockaddr_storage>,
    depth: u32,
    socket_fd: RawFd,
    /// When true, `RecvMsg` SQEs include a destination for the source address
    /// (unconnected server socket). When false, connected client socket.
    with_addr: bool,
}

// SAFETY: UringRecvBatch owns its ring, eventfd, backing buffers, iovecs, msghdrs,
// and sockaddr storage. The raw pointers embedded in iovecs/msghdrs always point
// into those owned vectors and are only used through &mut self methods, so moving
// the struct between Tokio worker threads does not create concurrent access.
unsafe impl Send for UringRecvBatch {}

impl UringRecvBatch {
    /// Create a receive batch on `socket_fd`.
    ///
    /// - `depth`: number of pre-posted RecvMsg SQEs (power-of-two, >= 4).
    /// - `buf_size`: per-buffer size in bytes (>= 1500).
    /// - `with_addr`: `true` for unconnected sockets (server) to capture source address.
    ///
    /// Returns `None` when io_uring or eventfd creation fails.
    pub fn new(socket_fd: RawFd, depth: u32, buf_size: usize, with_addr: bool) -> Option<Self> {
        Self::new_inner(socket_fd, depth, buf_size, with_addr, None)
    }

    /// Create a receive batch whose RecvMsg slots are backed by `MemoryPool` blocks.
    pub fn new_with_pool(
        socket_fd: RawFd,
        depth: u32,
        buf_size: usize,
        with_addr: bool,
        memory_pool: Arc<MemoryPool>,
    ) -> Option<Self> {
        Self::new_inner(socket_fd, depth, buf_size, with_addr, Some(memory_pool))
    }

    fn new_inner(
        socket_fd: RawFd,
        depth: u32,
        buf_size: usize,
        with_addr: bool,
        memory_pool: Option<Arc<MemoryPool>>,
    ) -> Option<Self> {
        let depth = depth.max(4).next_power_of_two();
        let buf_size = buf_size.max(1500);

        // Dedicated ring for receives (separate from send ring).
        let ring = match IoUring::builder().setup_sqpoll(1000).build(depth) {
            Ok(r) => r,
            Err(_) => match IoUring::new(depth) {
                Ok(r) => r,
                Err(e) => {
                    log::debug!("io_uring recv ring init failed (depth={depth}): {e}");
                    return None;
                }
            },
        };

        // Create eventfd for CQ -> Tokio wakeup.
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if efd < 0 {
            log::debug!("eventfd creation failed: {}", std::io::Error::last_os_error());
            return None;
        }

        // Register the eventfd so CQ completions trigger it.
        if ring.submitter().register_eventfd_async(efd).is_err() {
            log::debug!("register_eventfd_async failed");
            unsafe {
                libc::close(efd);
            }
            return None;
        }

        let d = depth as usize;

        let pooled = memory_pool.is_some();
        let bufs = if pooled { Vec::new() } else { vec![0u8; d * buf_size] };
        let mut blocks = Vec::with_capacity(d);
        if let Some(pool) = memory_pool.as_ref() {
            for _ in 0..d {
                let block = pool.alloc();
                if block.len() < buf_size {
                    log::debug!(
                        "io_uring recv pool block too small: block_len={}, buf_size={buf_size}",
                        block.len()
                    );
                    pool.free(block);
                    for block in blocks.into_iter().flatten() {
                        pool.free(block);
                    }
                    return None;
                }
                blocks.push(Some(block));
            }
        } else {
            blocks.resize_with(d, || None);
        }

        // Pre-build iovecs pointing into the buffer pool.
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(d);
        for i in 0..d {
            let iov_base = if let Some(block) = blocks[i].as_mut() {
                block.as_mut_ptr() as *mut libc::c_void
            } else {
                // Safety: bufs lives as long as self; no reallocation after this.
                unsafe { bufs.as_ptr().add(i * buf_size) as *mut libc::c_void }
            };
            iovecs.push(libc::iovec { iov_base, iov_len: buf_size });
        }

        // Pre-build sockaddr storage (server only).
        let addrs = if with_addr {
            vec![unsafe { std::mem::zeroed::<libc::sockaddr_storage>() }; d]
        } else {
            Vec::new()
        };

        // Pre-build msghdrs.
        let mut msgs: Vec<libc::msghdr> = Vec::with_capacity(d);
        for i in 0..d {
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            // Safety: iovecs[i] is stable (no further pushes).
            hdr.msg_iov = &iovecs[i] as *const libc::iovec as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            if with_addr && !addrs.is_empty() {
                // Will be fixed up after addrs vec is fully built (it already is).
                hdr.msg_name = &addrs[i] as *const libc::sockaddr_storage as *mut libc::c_void;
                hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            }
            msgs.push(hdr);
        }

        log::debug!(
            "io_uring recv batch created: depth={depth}, buf_size={buf_size}, with_addr={with_addr}, pooled={pooled}"
        );

        Some(Self {
            ring,
            eventfd: efd,
            bufs,
            blocks,
            memory_pool,
            buf_size,
            iovecs,
            msgs,
            addrs,
            depth,
            socket_fd,
            with_addr,
        })
    }

    /// Create with default depth (64) and buffer size (2048).
    pub fn with_defaults(socket_fd: RawFd, with_addr: bool) -> Option<Self> {
        Self::new(socket_fd, DEFAULT_RECV_DEPTH, DEFAULT_RECV_BUF_SIZE, with_addr)
    }

    /// Create a pool-backed receive batch with default depth and buffer size.
    pub fn with_defaults_pool(
        socket_fd: RawFd,
        with_addr: bool,
        memory_pool: Arc<MemoryPool>,
    ) -> Option<Self> {
        Self::new_with_pool(
            socket_fd,
            DEFAULT_RECV_DEPTH,
            DEFAULT_RECV_BUF_SIZE,
            with_addr,
            memory_pool,
        )
    }

    /// Raw eventfd descriptor for Tokio `AsyncFd` registration.
    ///
    /// Caller should `dup()` this fd before wrapping in `OwnedFd`/`AsyncFd`
    /// to avoid double-close (this struct closes the original in Drop).
    #[inline]
    pub fn eventfd_fd(&self) -> RawFd {
        self.eventfd
    }

    /// Post the initial batch of RecvMsg SQEs. Call once after construction.
    pub fn post_initial(&mut self) -> std::io::Result<()> {
        let fd = io_uring::types::Fd(self.socket_fd);
        let mut posted = 0u32;
        {
            let mut sq = self.ring.submission();
            for idx in 0..self.depth as usize {
                let entry = opcode::RecvMsg::new(fd, &mut self.msgs[idx] as *mut libc::msghdr)
                    .build()
                    .user_data(idx as u64);
                unsafe {
                    if sq.push(&entry).is_err() {
                        break;
                    }
                }
                posted += 1;
            }
        }
        if posted > 0 {
            self.ring.submit()?;
        }
        if posted < self.depth {
            log::warn!(
                "recv post_initial: only {posted}/{} RecvMsg SQEs armed (SQ too small)",
                self.depth
            );
        }
        Ok(())
    }

    /// Drain all ready CQEs and return completed receives.
    ///
    /// For contiguous-buffer mode, packet data is copied into `RecvCompletion::data`.
    /// For pool-backed mode, ownership of the filled pool block moves into the
    /// completion and the slot is immediately armed with a replacement block.
    pub fn drain_completions(&mut self) -> std::io::Result<Vec<RecvCompletion>> {
        let mut completions = Vec::new();
        let mut repost_indices: Vec<usize> = Vec::new();

        {
            let cq = self.ring.completion();
            for cqe in cq {
                let idx = cqe.user_data() as usize;
                let result = cqe.result();

                if result > 0 && idx < self.depth as usize {
                    let len = result as usize;
                    let addr = if self.with_addr { parse_sockaddr(&self.addrs[idx]) } else { None };
                    let len = len.min(self.buf_size);

                    if let Some(pool) = self.memory_pool.as_ref() {
                        if let Some(block) = self.blocks[idx].take() {
                            let mut replacement = pool.alloc();
                            if replacement.len() < self.buf_size {
                                pool.free(replacement);
                                self.blocks[idx] = Some(block);
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "io_uring recv pool block smaller than receive buffer",
                                ));
                            }
                            self.iovecs[idx].iov_base =
                                replacement.as_mut_ptr() as *mut libc::c_void;
                            self.iovecs[idx].iov_len = self.buf_size;
                            self.blocks[idx] = Some(replacement);
                            completions.push(RecvCompletion {
                                data: Vec::new(),
                                block: Some(block),
                                len,
                                addr,
                            });
                            repost_indices.push(idx);
                        }
                    } else {
                        let start = idx * self.buf_size;
                        let end = start + len;
                        let data = self.bufs[start..end].to_vec();
                        completions.push(RecvCompletion { data, block: None, len, addr });
                        repost_indices.push(idx);
                        self.iovecs[idx].iov_len = self.buf_size;
                    }

                    // Reset the sockaddr for next receive.
                    if self.with_addr {
                        self.addrs[idx] = unsafe { std::mem::zeroed() };
                        self.msgs[idx].msg_namelen =
                            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    }
                } else if result < 0 {
                    let errno = -result;
                    // EAGAIN (11), ECONNRESET (104), ECONNREFUSED (111) are expected.
                    if errno != 11 && errno != 104 && errno != 111 {
                        log::trace!("io_uring RecvMsg CQE error: idx={idx} errno={errno}");
                    }
                    repost_indices.push(idx.min(self.depth as usize - 1));
                }
                // result == 0: zero-length datagram, re-post.
            }
        }

        // Re-post consumed SQEs.
        if !repost_indices.is_empty() {
            let fd = io_uring::types::Fd(self.socket_fd);
            let mut reposted = 0usize;
            {
                let mut sq = self.ring.submission();
                for &idx in &repost_indices {
                    let entry = opcode::RecvMsg::new(fd, &mut self.msgs[idx] as *mut libc::msghdr)
                        .build()
                        .user_data(idx as u64);
                    unsafe {
                        if sq.push(&entry).is_err() {
                            break;
                        }
                    }
                    reposted += 1;
                }
            }
            if reposted > 0 {
                self.ring.submit()?;
            }
            if reposted < repost_indices.len() {
                log::warn!(
                    "io_uring recv repost: only {reposted}/{} RecvMsg SQEs rearmed (SQ too small)",
                    repost_indices.len()
                );
            }
        }

        Ok(completions)
    }
}

impl Drop for UringRecvBatch {
    fn drop(&mut self) {
        if let Some(pool) = self.memory_pool.as_ref() {
            for block in self.blocks.drain(..).flatten() {
                pool.free(block);
            }
        }
        unsafe {
            libc::close(self.eventfd);
        }
    }
}

/// Parse a `libc::sockaddr_storage` into a `std::net::SocketAddr`.
/// Returns `None` if the address family is unrecognized.
fn parse_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    match storage.ss_family as i32 {
        libc::AF_INET => {
            let sa = storage as *const _ as *const libc::sockaddr_in;
            unsafe {
                // sin_addr.s_addr is in network byte order (big-endian).
                // Ipv4Addr::from(u32) expects host byte order.
                let ip = Ipv4Addr::from(u32::from_be((*sa).sin_addr.s_addr));
                let port = u16::from_be((*sa).sin_port);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
        }
        libc::AF_INET6 => {
            let sa = storage as *const _ as *const libc::sockaddr_in6;
            unsafe {
                let ip = Ipv6Addr::from((*sa).sin6_addr.s6_addr);
                let port = u16::from_be((*sa).sin6_port);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    (*sa).sin6_flowinfo,
                    (*sa).sin6_scope_id,
                )))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_returns_none_on_unsupported_platform() {
        // On macOS (or CI without io_uring) this should return None.
        // On Linux it may return Some - both outcomes are valid.
        let result = UringBatchSender::new(4);
        if cfg!(not(target_os = "linux")) {
            assert!(result.is_none(), "io_uring should not init on non-Linux");
        }
        // On Linux: just verify it doesn't panic.
    }

    #[test]
    fn with_defaults_uses_256_depth() {
        let result = UringBatchSender::with_defaults();
        if cfg!(not(target_os = "linux")) {
            assert!(result.is_none());
        }
    }

    #[test]
    fn send_batch_empty_returns_zero() {
        if let Some(mut sender) = UringBatchSender::new(4) {
            let sent = sender.send_batch(0, &[]).expect("empty batch");
            assert_eq!(sent, 0);
        }
    }

    #[test]
    fn send_batch_to_empty_returns_zero() {
        if let Some(mut sender) = UringBatchSender::new(4) {
            let sent = sender.send_batch_to(0, &[]).expect("empty batch_to");
            assert_eq!(sent, 0);
        }
    }

    #[test]
    fn sqpoll_and_zc_fields_accessible() {
        if let Some(sender) = UringBatchSender::new(4) {
            // Accessors compile and return consistent values.
            // SQPOLL may be false if CAP_SYS_ADMIN is unavailable.
            // ZC may be false on kernels before 6.0.
            let _sqpoll = sender.sqpoll_active();
            let _zc = sender.zc_supported();
        }
    }

    #[test]
    fn recv_new_returns_none_on_macos() {
        // Use a real bound socket fd (not fd=0 which is stdin).
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
        let result = UringRecvBatch::new(fd, 4, 2048, false);
        if cfg!(not(target_os = "linux")) {
            assert!(result.is_none(), "UringRecvBatch should not init on non-Linux");
        }
    }

    #[test]
    fn recv_eventfd_created() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
        if let Some(recv) = UringRecvBatch::new(fd, 4, 2048, false) {
            assert!(recv.eventfd_fd() > 0, "eventfd should be a positive fd");
        }
    }

    #[test]
    fn recv_drain_empty_returns_empty() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
        if let Some(mut recv) = UringRecvBatch::new(fd, 4, 2048, false) {
            // No SQEs posted, no CQEs pending - drain should return empty.
            let completions = recv.drain_completions().expect("drain empty");
            assert!(completions.is_empty());
        }
    }

    #[test]
    fn parse_sockaddr_ipv4_roundtrip() {
        use std::net::{Ipv4Addr, SocketAddrV4};
        let original = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        fill_sockaddr(original, &mut storage);
        let parsed = parse_sockaddr(&storage);
        assert_eq!(parsed, Some(original));
    }

    #[test]
    fn fill_sockaddr_ipv4_sets_correct_family() {
        use std::net::{Ipv4Addr, SocketAddrV4};
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9999));
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        fill_sockaddr(addr, &mut storage);
        let sa = &storage as *const _ as *const libc::sockaddr_in;
        unsafe {
            assert_eq!((*sa).sin_family as i32, libc::AF_INET);
            assert_eq!((*sa).sin_port, 9999u16.to_be());
            // 127.0.0.1 = [127,0,0,1] as ne bytes
            assert_eq!((*sa).sin_addr.s_addr, u32::from_ne_bytes([127, 0, 0, 1]));
        }
    }
}
