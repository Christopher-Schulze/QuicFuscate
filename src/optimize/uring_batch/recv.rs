use super::*;

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
    /// Optional so Drop can destroy the ring before returning pool-backed
    /// buffers to `MemoryPool`.
    ring: Option<IoUring>,
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
    /// Slots whose completed operation still need one replacement RecvMsg SQE.
    repost_pending: Vec<bool>,
    /// Slots currently owned by the kernel. This is used only for audit/state
    /// validation and makes duplicate CQEs fail closed.
    armed: Vec<bool>,
    /// Test-only count of successful zero-length UDP receives consumed by the
    /// kernel. Empty datagrams are intentionally not forwarded to the QUIC
    /// parser, but the Linux re-arm regression must still observe their CQEs.
    #[cfg(test)]
    zero_length_completions: usize,
}

// SAFETY: UringRecvBatch owns its ring, eventfd, backing buffers, iovecs, msghdrs,
// and sockaddr storage. The raw pointers embedded in iovecs/msghdrs always point
// into those owned allocations and are only used through &mut self methods. Drop
// destroys the ring before pool buffers are returned, so moving the struct between
// Tokio worker threads does not create concurrent access or a dangling pointer.
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
        let depth = depth.max(4).checked_next_power_of_two()?;
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
        // SAFETY: eventfd(2) takes an initial count (0) and valid flags; both
        // EFD_NONBLOCK and EFD_CLOEXEC are valid flag constants. The returned fd
        // is checked for < 0 immediately after.
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if efd < 0 {
            log::debug!("eventfd creation failed: {}", std::io::Error::last_os_error());
            return None;
        }

        // Register the eventfd so CQ completions trigger it.
        if ring.submitter().register_eventfd_async(efd).is_err() {
            log::debug!("register_eventfd_async failed");
            // SAFETY: efd is a valid open fd from the eventfd() call above and
            // is not used after this close.
            unsafe {
                libc::close(efd);
            }
            return None;
        }

        let d = depth as usize;
        let total_buf_size = match d.checked_mul(buf_size) {
            Some(total_buf_size) => total_buf_size,
            None => {
                // SAFETY: efd is the valid eventfd created above and no ring
                // request has been submitted yet.
                unsafe {
                    libc::close(efd);
                }
                return None;
            }
        };

        let pooled = memory_pool.is_some();
        let bufs = if pooled { Vec::new() } else { vec![0u8; total_buf_size] };
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
                    // SAFETY: efd is the valid eventfd created above and no
                    // ring request has been submitted yet.
                    unsafe {
                        libc::close(efd);
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
        for (i, block_slot) in blocks.iter_mut().enumerate().take(d) {
            let iov_base = if let Some(block) = block_slot.as_mut() {
                block.as_mut_ptr() as *mut libc::c_void
            } else {
                // SAFETY: bufs lives as long as self; no reallocation after this.
                // The offset i * buf_size is within the allocated d * buf_size bytes.
                unsafe { bufs.as_ptr().add(i * buf_size) as *mut libc::c_void }
            };
            iovecs.push(libc::iovec { iov_base, iov_len: buf_size });
        }

        // Pre-build sockaddr storage (server only).
        let addrs = if with_addr {
            // SAFETY: sockaddr_storage is POD; an all-zero bit pattern is a valid
            // value (zeroed ss_family is ignored until fill_sockaddr writes it).
            vec![unsafe { std::mem::zeroed::<libc::sockaddr_storage>() }; d]
        } else {
            Vec::new()
        };

        // Pre-build msghdrs.
        let mut msgs: Vec<libc::msghdr> = Vec::with_capacity(d);
        for i in 0..d {
            // SAFETY: msghdr is POD; an all-zero bit pattern produces valid
            // null/zero fields (msg_name, msg_control, msg_flags).
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            // SAFETY: iovecs[i] is stable (no further pushes).
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
            ring: Some(ring),
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
            repost_pending: vec![false; d],
            armed: vec![false; d],
            #[cfg(test)]
            zero_length_completions: 0,
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

    #[cfg(test)]
    #[inline]
    pub(super) fn zero_length_completions_seen(&self) -> usize {
        self.zero_length_completions
    }

    /// Post the initial batch of RecvMsg SQEs. Call once after construction.
    pub fn post_initial(&mut self) -> std::io::Result<()> {
        let fd = io_uring::types::Fd(self.socket_fd);
        let mut posted = 0u32;
        let Some(ring) = self.ring.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "io_uring receive ring is closed",
            ));
        };
        {
            let mut sq = ring.submission();
            for idx in 0..self.depth as usize {
                let entry = opcode::RecvMsg::new(fd, &mut self.msgs[idx] as *mut libc::msghdr)
                    .build()
                    .user_data(idx as u64);
                // SAFETY: msgs[idx] points into the stable self.msgs Vec and
                // its iovec points into self.bufs/blocks; all outlive the kernel
                // completion. The SQE is pushed within a single submission borrow.
                unsafe {
                    if sq.push(&entry).is_err() {
                        break;
                    }
                }
                posted += 1;
            }
        }
        let submit_result = if posted > 0 { ring.submit() } else { Ok(0) };
        for idx in 0..posted as usize {
            self.armed[idx] = true;
        }
        submit_result?;
        if posted < self.depth {
            log::warn!(
                "recv post_initial: only {posted}/{} RecvMsg SQEs armed (SQ too small)",
                self.depth
            );
            for idx in posted as usize..self.depth as usize {
                self.repost_pending[idx] = true;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "io_uring receive ring could not arm every initial slot",
            ));
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
        let Some(ring) = self.ring.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "io_uring receive ring is closed",
            ));
        };
        let mut drain_error = None;

        {
            let cq = ring.completion();
            for cqe in cq {
                let idx = match checked_slot_index(cqe.user_data(), self.depth as usize) {
                    Ok(idx) => idx,
                    Err(error) => {
                        drain_error = Some(error);
                        continue;
                    }
                };
                if !self.armed[idx] || self.repost_pending[idx] {
                    drain_error = Some(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("duplicate or unarmed io_uring receive slot: {idx}"),
                    ));
                    continue;
                }
                self.armed[idx] = false;
                self.repost_pending[idx] = true;
                let result = cqe.result();

                if result > 0 {
                    let len = result as usize;
                    let addr = if self.with_addr { parse_sockaddr(&self.addrs[idx]) } else { None };
                    let len = len.min(self.buf_size);

                    if let Some(pool) = self.memory_pool.as_ref() {
                        let Some(block) = self.blocks[idx].take() else {
                            drain_error = Some(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("io_uring receive pool slot {idx} has no backing block"),
                            ));
                            continue;
                        };
                        let mut replacement = pool.alloc();
                        if replacement.len() < self.buf_size {
                            pool.free(replacement);
                            self.blocks[idx] = Some(block);
                            drain_error = Some(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "io_uring recv pool block smaller than receive buffer",
                            ));
                            continue;
                        }
                        self.iovecs[idx].iov_base = replacement.as_mut_ptr() as *mut libc::c_void;
                        self.iovecs[idx].iov_len = self.buf_size;
                        self.blocks[idx] = Some(replacement);
                        completions.push(RecvCompletion {
                            data: Vec::new(),
                            block: Some(block),
                            len,
                            addr,
                        });
                    } else {
                        let start = idx * self.buf_size;
                        let end = start + len;
                        let data = self.bufs[start..end].to_vec();
                        completions.push(RecvCompletion { data, block: None, len, addr });
                        self.iovecs[idx].iov_len = self.buf_size;
                    }
                } else {
                    #[cfg(test)]
                    if result == 0 {
                        self.zero_length_completions += 1;
                    }
                    if result < 0 {
                        let errno = result.unsigned_abs();
                        // EAGAIN (11), ECONNRESET (104), ECONNREFUSED (111) are expected.
                        if errno != 11 && errno != 104 && errno != 111 {
                            log::trace!("io_uring RecvMsg CQE error: idx={idx} errno={errno}");
                        }
                    }
                    // A zero-length datagram is a consumed receive and must
                    // re-arm the same slot exactly like an error completion.
                    self.iovecs[idx].iov_len = self.buf_size;
                }
                // Reset the sockaddr for every consumed receive, including
                // zero-length datagrams and negative CQEs, so stale address
                // bytes cannot leak into the next RecvMsg operation.
                if self.with_addr {
                    // SAFETY: sockaddr_storage is POD; zeroing is valid and
                    // clears stale address data before the next RecvMsg.
                    self.addrs[idx] = unsafe { std::mem::zeroed() };
                    self.msgs[idx].msg_namelen =
                        std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                }
            }
        }

        if let Some(error) = drain_error {
            return Err(error);
        }

        // Re-post every consumed slot at most once. Pending slots remain
        // marked if the submission queue is temporarily full and are retried
        // on the next drain instead of being silently lost.
        let fd = io_uring::types::Fd(self.socket_fd);
        let mut reposted = 0usize;
        {
            let mut sq = ring.submission();
            for idx in 0..self.depth as usize {
                if !self.repost_pending[idx] {
                    continue;
                }
                let entry = opcode::RecvMsg::new(fd, &mut self.msgs[idx] as *mut libc::msghdr)
                    .build()
                    .user_data(idx as u64);
                // SAFETY: msgs[idx] points into the stable self.msgs Vec and
                // its iovec points into self.bufs/blocks; all outlive the
                // kernel completion. The SQE is pushed within one submission
                // borrow, and the slot remains armed until its CQE is drained.
                unsafe {
                    if sq.push(&entry).is_err() {
                        break;
                    }
                }
                self.repost_pending[idx] = false;
                self.armed[idx] = true;
                reposted += 1;
            }
        }
        let submit_result = if reposted > 0 { ring.submit() } else { Ok(0) };
        submit_result?;

        let pending = self.repost_pending.iter().filter(|pending| **pending).count();
        if pending > 0 {
            log::warn!(
                "io_uring recv repost: {reposted} submitted, {pending} slots remain pending"
            );
        }
        Ok(completions)
    }
}

impl Drop for UringRecvBatch {
    fn drop(&mut self) {
        // Destroy the ring before returning pool blocks or dropping contiguous
        // buffers. The io_uring owner is then gone before any kernel request
        // can retain a pointer into those allocations, including when a
        // cancellation syscall is unavailable on an older kernel.
        drop(self.ring.take());

        if let Some(pool) = self.memory_pool.as_ref() {
            for block in self.blocks.drain(..).flatten() {
                pool.free(block);
            }
        }
        // SAFETY: self.eventfd is a valid open fd created during construction
        // and the ring has already been destroyed, so no completion can use it.
        unsafe {
            libc::close(self.eventfd);
        }
    }
}
