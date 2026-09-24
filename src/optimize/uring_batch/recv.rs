use super::*;

// Receive path: UringRecvBatch
// ---------------------------------------------------------------------------

/// Default receive queue depth (pre-posted RecvMsg SQEs).
const DEFAULT_RECV_DEPTH: u32 = 64;
/// Default per-buffer size (power-of-two, > typical MTU).
const DEFAULT_RECV_BUF_SIZE: usize = 2048;
/// Per-buffer size that can hold a maximal `UDP_GRO` super-buffer.
const GRO_RECV_BUF_SIZE: usize = 65_535;
/// Per-slot ancillary storage: one `UDP_GRO` segment-size cmsg fits into
/// `CMSG_SPACE(sizeof(u16))` <= 32 bytes on every supported kernel ABI.
const CMSG_SLOT_BYTES: usize = 32;

/// Control-message slot aligned for `libc::cmsghdr` access.
#[repr(align(8))]
#[derive(Clone, Copy)]
struct CmsgSlot([u8; CMSG_SLOT_BYTES]);

impl CmsgSlot {
    const ZEROED: Self = Self([0u8; CMSG_SLOT_BYTES]);
}

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
    /// Per-slot ancillary storage so a `UDP_GRO` segment-size cmsg survives the
    /// completion. Always armed; the socket option decides whether the kernel
    /// actually fills it.
    cmsgs: Vec<CmsgSlot>,
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

        // Dedicated ring for receives (separate from send ring). SQPOLL is
        // opt-in (QUICFUSCATE_IO_URING_SQPOLL=1): its kernel poller thread
        // survives privilege transitions and fails post-drop UID verification
        // in the server role, so the portable default is a standard ring.
        let sqpoll_opt_in =
            crate::env_utils::EnvSnapshot::capture().flag("QUICFUSCATE_IO_URING_SQPOLL", false);
        let ring = if sqpoll_opt_in {
            match IoUring::builder().setup_sqpoll(1000).build(depth) {
                Ok(r) => r,
                Err(_) => match IoUring::new(depth) {
                    Ok(r) => r,
                    Err(e) => {
                        log::debug!("io_uring recv ring init failed (depth={depth}): {e}");
                        return None;
                    }
                },
            }
        } else {
            match IoUring::new(depth) {
                Ok(r) => r,
                Err(e) => {
                    log::debug!("io_uring recv ring init failed (depth={depth}): {e}");
                    return None;
                }
            }
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

        // Register the eventfd so CQ completions trigger it. Plain
        // IORING_REGISTER_EVENTFD (not _ASYNC): the async variant only
        // signals worker-pool completions, while socket recv requests finish
        // through the kernel's poll path and never raise the async eventfd.
        if ring.submitter().register_eventfd(efd).is_err() {
            log::debug!("register_eventfd failed");
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

        // Per-slot ancillary storage for the `UDP_GRO` segment-size cmsg. The
        // storage is always armed so a socket can enable `UDP_GRO` without
        // receiver changes; when the socket option is off the kernel simply
        // reports `msg_controllen == 0`.
        let mut cmsgs = vec![CmsgSlot::ZEROED; d];

        // Pre-build msghdrs.
        let mut msgs: Vec<libc::msghdr> = Vec::with_capacity(d);
        for i in 0..d {
            // SAFETY: msghdr is POD; an all-zero bit pattern produces valid
            // null/zero fields (msg_name, msg_flags).
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            // SAFETY: iovecs[i] is stable (no further pushes).
            hdr.msg_iov = &iovecs[i] as *const libc::iovec as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            // SAFETY: cmsgs[i] is stable (no further pushes) and aligned for
            // cmsghdr access via `CmsgSlot`'s 8-byte alignment.
            hdr.msg_control = cmsgs[i].0.as_mut_ptr() as *mut libc::c_void;
            hdr.msg_controllen = CMSG_SLOT_BYTES;
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
            cmsgs,
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

    /// Create a contiguous receive batch sized for `UDP_GRO` super-buffers.
    ///
    /// Requires the caller to have enabled `UDP_GRO` on the socket. Contiguous
    /// mode is used on purpose: pool blocks are MTU-sized and cannot hold a
    /// maximal 65,535-byte coalesced buffer.
    pub fn with_defaults_gro(socket_fd: RawFd, with_addr: bool) -> Option<Self> {
        Self::new(socket_fd, DEFAULT_RECV_DEPTH, GRO_RECV_BUF_SIZE, with_addr)
    }

    /// Extract the `UDP_GRO` segment size reported for `slot`, if any.
    ///
    /// Returns `Some(gso_size)` when the kernel attached a `UDP_GRO` cmsg with
    /// a sane segment size (non-zero, not larger than the receive buffer).
    /// Takes `msgs`/`cmsgs` directly so the drain loop can call it while
    /// `self.ring` stays mutably borrowed. The control pointer must still
    /// address this batch's own slot storage; anything else fails closed.
    fn gro_segment_size(
        msgs: &[libc::msghdr],
        cmsgs: &[CmsgSlot],
        slot: usize,
        buf_size: usize,
    ) -> Option<usize> {
        let msg = &msgs[slot];
        if msg.msg_control as *const u8 != cmsgs[slot].0.as_ptr() {
            log::warn!("io_uring recv slot {slot} control pointer escaped its slot storage");
            return None;
        }
        if msg.msg_controllen < std::mem::size_of::<libc::cmsghdr>()
            || msg.msg_controllen > CMSG_SLOT_BYTES
        {
            return None;
        }
        // SAFETY: the kernel wrote a valid cmsg chain into the slot's control
        // buffer bounded by msg_controllen; CMSG_FIRSTHDR/CMSG_NXTHDR walk it.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
                    let size = *(libc::CMSG_DATA(cmsg) as *const u16) as usize;
                    return (size > 0 && size <= buf_size).then_some(size);
                }
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }
        }
        None
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
                    let gso_size =
                        Self::gro_segment_size(&self.msgs, &self.cmsgs, idx, self.buf_size)
                            .filter(|size| len > *size);

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
                        if let Some(gso_size) = gso_size {
                            // Kernel-coalesced super-buffer: one completion per
                            // original segment, each copied into its own pool
                            // block so the downstream per-datagram contract
                            // stays unchanged.
                            let mut offset = 0usize;
                            while offset < len {
                                let seg_len = (len - offset).min(gso_size);
                                let mut segment = pool.alloc();
                                if segment.len() < seg_len {
                                    pool.free(segment);
                                    pool.free(block);
                                    drain_error = Some(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "io_uring recv pool block smaller than GRO segment",
                                    ));
                                    break;
                                }
                                segment[..seg_len]
                                    .copy_from_slice(&block[offset..offset + seg_len]);
                                completions.push(RecvCompletion {
                                    data: Vec::new(),
                                    block: Some(segment),
                                    len: seg_len,
                                    addr,
                                });
                                offset += seg_len;
                            }
                        } else {
                            completions.push(RecvCompletion {
                                data: Vec::new(),
                                block: Some(block),
                                len,
                                addr,
                            });
                        }
                    } else {
                        let start = idx * self.buf_size;
                        if let Some(gso_size) = gso_size {
                            // One completion per original segment; the copies
                            // restore the per-datagram contract while the
                            // single RecvMsg already saved the syscalls.
                            let mut offset = start;
                            while offset < start + len {
                                let seg_len = (start + len - offset).min(gso_size);
                                let data = self.bufs[offset..offset + seg_len].to_vec();
                                completions.push(RecvCompletion {
                                    data,
                                    block: None,
                                    len: seg_len,
                                    addr,
                                });
                                offset += seg_len;
                            }
                        } else {
                            let end = start + len;
                            let data = self.bufs[start..end].to_vec();
                            completions.push(RecvCompletion { data, block: None, len, addr });
                        }
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
                // The kernel shrinks msg_controllen and may set MSG_TRUNC in
                // msg_flags; re-arm the full cmsg slot before the repost.
                self.msgs[idx].msg_controllen = CMSG_SLOT_BYTES;
                self.msgs[idx].msg_flags = 0;
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

// Receive path: UringRecvMultishot (provided-buffer ring + RecvMulti)
// ---------------------------------------------------------------------------
//
// TODO-1007: one `RecvMulti` SQE (`IORING_OP_RECV` + `IORING_RECV_MULTISHOT` +
// `IOSQE_BUFFER_SELECT`) produces repeated CQEs, each picking a buffer from a
// registered provided-buffer ring. Compared to `UringRecvBatch` this removes
// the per-packet re-arm entirely: no per-slot msghdr/iovec state, no
// `repost_pending` bookkeeping, one SQE instead of N per drain cycle.
//
// Constraint: `IORING_OP_RECV` carries no `msghdr`, so neither a per-packet
// source address nor a `UDP_GRO` segment-size cmsg is available. This type is
// therefore for connected sockets only, and the caller must NOT enable
// `UDP_GRO` on the socket - a coalesced super-buffer would arrive without its
// segment size and could not be split back into datagrams.

/// Buffer-group id registered for the multishot receive ring.
const MULTISHOT_BGID: u16 = 7;
/// user_data tag carried by the single multishot request. Dedicated ring, so
/// every CQE must carry this tag.
const MULTISHOT_TAG: u64 = u64::MAX;

/// One `io_uring_buf` ring entry (16 bytes). The provided-buffer ring is an
/// mmap'd array of these; the ring tail aliases `bufs[0].resv` (kernel reads
/// addr/len/bid only), so entries are written field-wise and `resv` is never
/// touched - writing it would clobber the shared tail word.
#[repr(C)]
struct BufRingBuf {
    addr: u64,
    len: u32,
    bid: u16,
    resv_tail: u16,
}

const BUF_RING_ENTRY_BYTES: usize = std::mem::size_of::<BufRingBuf>();
/// Byte offset of the shared tail u16 inside the ring mapping (the `tail`
/// field of `struct io_uring_buf_ring`, aliasing `bufs[0].resv`).
const BUF_RING_TAIL_OFFSET: usize = 14;

/// Multishot UDP receiver backed by a dedicated io_uring ring, a provided
/// buffer ring, and the same eventfd bridge as `UringRecvBatch`.
///
/// Connected sockets only. The kernel pulls one buffer per datagram from the
/// ring; completions report the buffer id via `IORING_CQE_F_BUFFER`. Consumed
/// buffers are pushed back onto the ring tail and the tail is advanced once
/// per drain batch.
pub struct UringRecvMultishot {
    /// Optional so Drop can destroy the ring before unmapping the provided
    /// buffer ring and returning pool-backed buffers.
    ring: Option<IoUring>,
    /// eventfd created with `EFD_NONBLOCK | EFD_CLOEXEC`, registered via
    /// `register_eventfd_async`. Owned by this struct (closed in Drop).
    eventfd: RawFd,
    /// mmap'd provided-buffer ring (`entries * 16` bytes).
    ring_map: *mut u8,
    /// Number of ring entries (power of two, <= 32768).
    ring_entries: u16,
    /// Producer-side tail we publish to the kernel via the shared tail word.
    local_tail: u16,
    /// Contiguous buffer pool: `entries * buf_size` bytes when not pooled.
    bufs: Vec<u8>,
    /// Pool-backed buffers indexed by buffer id when pooled.
    blocks: Vec<Option<AlignedBox<[u8]>>>,
    memory_pool: Option<Arc<MemoryPool>>,
    buf_size: usize,
    socket_fd: RawFd,
    /// Whether the multishot request is currently armed.
    armed: bool,
    /// A completion without `IORING_CQE_F_MORE` terminated the request; it
    /// must be re-armed on the next drain.
    rearm_pending: bool,
    /// Total number of `-ENOBUFS` terminations observed (ring ran dry).
    ring_starved_total: u64,
    /// `(bid, backing addr)` pairs awaiting a ring re-add; collected during
    /// the drain and published with a single tail advance. In pooled mode the
    /// address is the freshly allocated replacement block.
    refill: Vec<(u16, *mut u8)>,
    #[cfg(test)]
    zero_length_completions: usize,
}

// SAFETY: UringRecvMultishot owns its ring, eventfd, the mapped provided-buffer
// ring and all backing buffers. Raw pointers into the mapping and backing are
// only used through &mut self methods. Drop destroys the io_uring ring before
// unmapping or freeing anything, so no kernel request can retain a pointer.
unsafe impl Send for UringRecvMultishot {}

impl UringRecvMultishot {
    /// Create a contiguous multishot receiver. `entries` is the provided-buffer
    /// ring depth (power of two, >= 8, <= 32768).
    pub fn new(socket_fd: RawFd, entries: u16, buf_size: usize) -> Option<Self> {
        Self::new_inner(socket_fd, entries, buf_size, None)
    }

    /// Create a multishot receiver whose buffers are `MemoryPool` blocks; the
    /// completed block moves into `RecvCompletion` (zero-copy into conn.recv).
    pub fn new_with_pool(
        socket_fd: RawFd,
        entries: u16,
        buf_size: usize,
        memory_pool: Arc<MemoryPool>,
    ) -> Option<Self> {
        Self::new_inner(socket_fd, entries, buf_size, Some(memory_pool))
    }

    fn new_inner(
        socket_fd: RawFd,
        entries: u16,
        buf_size: usize,
        memory_pool: Option<Arc<MemoryPool>>,
    ) -> Option<Self> {
        let entries = entries.max(8).checked_next_power_of_two()?;
        let buf_size = buf_size.max(1500);

        // CQ must hold the whole provided-buffer ring plus termination
        // headroom: a full CQ parks completions in the kernel overflow list,
        // including the terminating -ENOBUFS CQE, and that list only drains
        // into the visible CQ on the next io_uring_enter.
        let cqsize = (entries as u32).saturating_add(64).clamp(256, 32768);
        let ring = match IoUring::builder().setup_cqsize(cqsize).build(8) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("io_uring multishot recv ring init failed: {e}");
                return None;
            }
        };

        // SAFETY: eventfd(2) takes an initial count (0) and valid flags.
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if efd < 0 {
            log::debug!("eventfd creation failed: {}", std::io::Error::last_os_error());
            return None;
        }
        if ring.submitter().register_eventfd(efd).is_err() {
            log::debug!("register_eventfd failed");
            // SAFETY: efd is a valid open fd not used after this close.
            unsafe {
                libc::close(efd);
            }
            return None;
        }

        // Provided-buffer ring: entries * sizeof(io_uring_buf) anonymous map.
        let map_len = entries as usize * BUF_RING_ENTRY_BYTES;
        // SAFETY: mmap with a null hint, private anonymous mapping of map_len
        // bytes; the result is validated against MAP_FAILED before use.
        let ring_map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ring_map == libc::MAP_FAILED {
            log::debug!("buf ring mmap failed: {}", std::io::Error::last_os_error());
            // SAFETY: efd is a valid open fd not used after this close.
            unsafe {
                libc::close(efd);
            }
            return None;
        }

        // SAFETY: ring_map points to a live map_len-byte mapping that stays
        // valid until unregister + munmap in Drop; bgid is unique to this ring.
        if let Err(e) = unsafe {
            ring.submitter().register_buf_ring_with_flags(
                ring_map as u64,
                entries,
                MULTISHOT_BGID,
                0,
            )
        } {
            log::debug!("register_buf_ring failed: {e}");
            // SAFETY: ring_map/map_len describe the mapping created above.
            unsafe {
                libc::munmap(ring_map, map_len);
                libc::close(efd);
            }
            return None;
        }

        let d = entries as usize;
        let pooled = memory_pool.is_some();
        let mut this = Self {
            ring: Some(ring),
            eventfd: efd,
            ring_map: ring_map as *mut u8,
            ring_entries: entries,
            local_tail: 0,
            bufs: if pooled { Vec::new() } else { vec![0u8; d * buf_size] },
            blocks: Vec::new(),
            memory_pool,
            buf_size,
            socket_fd,
            armed: false,
            rearm_pending: false,
            ring_starved_total: 0,
            refill: Vec::with_capacity(d),
            #[cfg(test)]
            zero_length_completions: 0,
        };

        if let Some(pool) = this.memory_pool.as_ref() {
            let mut blocks: Vec<Option<AlignedBox<[u8]>>> = Vec::with_capacity(d);
            for _ in 0..d {
                let block = pool.alloc();
                if block.len() < buf_size {
                    pool.free(block);
                    for block in blocks.into_iter().flatten() {
                        pool.free(block);
                    }
                    // SAFETY: the io_uring ring is destroyed with `this` at the
                    // end of this scope; munmap/close release our own objects.
                    unsafe {
                        libc::munmap(this.ring_map as *mut libc::c_void, map_len);
                        libc::close(this.eventfd);
                    }
                    this.ring_map = std::ptr::null_mut();
                    return None;
                }
                blocks.push(Some(block));
            }
            this.blocks = blocks;
        } else {
            this.blocks.resize_with(d, || None);
        }

        // Offer every buffer id to the kernel, then publish one tail advance.
        for bid in 0..entries {
            // SAFETY: bid < entries indexes a slot whose backing was allocated
            // above; buffer_addr returns a live pointer into our storage.
            let addr = unsafe { Self::buffer_addr(&this.bufs, &this.blocks, this.buf_size, bid) };
            this.ring_add(bid, addr);
        }
        this.ring_advance();

        log::debug!(
            "io_uring multishot recv created: entries={entries}, buf_size={buf_size}, pooled={pooled}"
        );
        Some(this)
    }

    /// Backing pointer for a buffer id. Takes the backing fields directly so
    /// the drain loop can call it while `self.ring` stays mutably borrowed.
    ///
    /// SAFETY: bid must be < the number of backing slots and, in pooled mode,
    /// the slot must hold a block; the returned pointer is valid while the
    /// backing storage lives.
    unsafe fn buffer_addr(
        bufs: &[u8],
        blocks: &[Option<AlignedBox<[u8]>>],
        buf_size: usize,
        bid: u16,
    ) -> *mut u8 {
        let idx = bid as usize;
        if let Some(block) = blocks.get(idx).and_then(|slot| slot.as_ref()) {
            block.as_ptr() as *mut u8
        } else if !bufs.is_empty() {
            // SAFETY: idx < entries and bufs holds entries * buf_size bytes.
            unsafe { bufs.as_ptr().add(idx * buf_size) as *mut u8 }
        } else {
            std::ptr::null_mut()
        }
    }

    /// Stage a buffer id onto the ring tail without publishing it. Writes the
    /// three kernel-consumed fields individually so the shared `resv`/tail
    /// word at entry 0 is never clobbered.
    fn ring_add(&mut self, bid: u16, addr: *mut u8) {
        let idx = (self.local_tail & (self.ring_entries - 1)) as usize;
        // SAFETY: idx < ring_entries; entry is inside the map_len mapping.
        let entry = unsafe { self.ring_map.add(idx * BUF_RING_ENTRY_BYTES) as *mut BufRingBuf };
        // SAFETY: entry points into our live mapping; field-wise stores avoid
        // touching resv_tail which aliases the shared tail when idx == 0.
        unsafe {
            (*entry).addr = addr as u64;
            (*entry).len = self.buf_size as u32;
            (*entry).bid = bid;
        }
        self.local_tail = self.local_tail.wrapping_add(1);
    }

    /// Publish staged entries to the kernel with release ordering.
    fn ring_advance(&mut self) {
        // SAFETY: tail word lives at byte offset 14 of the mapping.
        let tail_ptr = unsafe { self.ring_map.add(BUF_RING_TAIL_OFFSET) as *mut u16 };
        std::sync::atomic::fence(Ordering::Release);
        // SAFETY: tail_ptr addresses the shared tail word inside our mapping.
        unsafe {
            std::ptr::write_volatile(tail_ptr, self.local_tail);
        }
    }

    /// Raw eventfd descriptor for Tokio `AsyncFd` registration.
    #[inline]
    pub fn eventfd_fd(&self) -> RawFd {
        self.eventfd
    }

    /// Total `-ENOBUFS` ring-starvation events observed since creation.
    #[inline]
    pub fn ring_starved_total(&self) -> u64 {
        self.ring_starved_total
    }

    /// Whether the multishot request is currently armed.
    #[inline]
    pub fn is_armed(&self) -> bool {
        self.armed
    }

    #[cfg(test)]
    #[inline]
    pub(super) fn zero_length_completions_seen(&self) -> usize {
        self.zero_length_completions
    }

    /// Arm the multishot receive request. Call once after construction; the
    /// request then produces CQEs until the kernel terminates it (no
    /// `IORING_CQE_F_MORE`), at which point `drain_completions` re-arms it.
    pub fn post_initial(&mut self) -> std::io::Result<()> {
        self.arm_multishot()
    }

    fn arm_multishot(&mut self) -> std::io::Result<()> {
        let Some(ring) = self.ring.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "io_uring multishot receive ring is closed",
            ));
        };
        let fd = io_uring::types::Fd(self.socket_fd);
        {
            let mut sq = ring.submission();
            let entry = opcode::RecvMulti::new(fd, MULTISHOT_BGID).build().user_data(MULTISHOT_TAG);
            // SAFETY: the SQE references our registered bgid; backing buffers
            // outlive the ring. Pushed within one submission borrow.
            unsafe {
                if sq.push(&entry).is_err() {
                    self.rearm_pending = true;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "io_uring multishot recv SQE could not be queued",
                    ));
                }
            }
        }
        ring.submit()?;
        self.armed = true;
        self.rearm_pending = false;
        Ok(())
    }

    /// Drain all ready CQEs and return completed receives.
    ///
    /// Each CFE with `IORING_CQE_F_BUFFER` consumed one ring buffer; the
    /// payload is either copied into `RecvCompletion::data` (contiguous mode)
    /// or moved out as the pool block itself (pooled mode). Consumed bids are
    /// re-staged and the tail advanced once per drain.
    pub fn drain_completions(&mut self) -> std::io::Result<Vec<RecvCompletion>> {
        let mut completions = Vec::new();
        let Some(ring) = self.ring.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "io_uring multishot receive ring is closed",
            ));
        };
        let mut drain_error = None;

        {
            let cq = ring.completion();
            for cqe in cq {
                if cqe.user_data() != MULTISHOT_TAG {
                    drain_error = Some(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "unexpected user_data on multishot recv ring: {:#x}",
                            cqe.user_data()
                        ),
                    ));
                    continue;
                }
                if !io_uring::cqueue::more(cqe.flags()) {
                    // The request terminated; it must be re-armed. A missing
                    // MORE flag accompanies both normal termination and
                    // -ENOBUFS.
                    self.armed = false;
                    self.rearm_pending = true;
                }
                let result = cqe.result();
                if result < 0 {
                    let errno = result.unsigned_abs();
                    // ENOBUFS (105): provided ring ran dry; counted and the
                    // re-arm above resumes reception after the refill below.
                    if errno == 105 {
                        self.ring_starved_total += 1;
                    } else if errno != 11 && errno != 104 && errno != 111 {
                        log::trace!("io_uring RecvMulti CQE error: errno={errno}");
                    }
                    continue;
                }
                if result == 0 {
                    // Zero-length datagram. The kernel may or may not attach a
                    // buffer id (kernel-version dependent): recycle the bid
                    // when one was consumed, count the receive either way.
                    #[cfg(test)]
                    {
                        self.zero_length_completions += 1;
                    }
                    if let Some(bid) = io_uring::cqueue::buffer_select(cqe.flags()) {
                        if bid < self.ring_entries {
                            // SAFETY: backing for bid is unchanged.
                            let addr = unsafe {
                                Self::buffer_addr(&self.bufs, &self.blocks, self.buf_size, bid)
                            };
                            if !addr.is_null() {
                                self.refill.push((bid, addr));
                            }
                        }
                    }
                    continue;
                }
                let Some(bid) = io_uring::cqueue::buffer_select(cqe.flags()) else {
                    drain_error = Some(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "io_uring multishot CQE carried no buffer id",
                    ));
                    continue;
                };
                if bid >= self.ring_entries {
                    drain_error = Some(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("io_uring multishot buffer id {bid} out of range"),
                    ));
                    continue;
                }
                let len = (result as usize).min(self.buf_size);
                if let Some(pool) = self.memory_pool.as_ref() {
                    let idx = bid as usize;
                    let Some(block) = self.blocks[idx].take() else {
                        drain_error = Some(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("io_uring multishot pool slot {bid} has no backing block"),
                        ));
                        continue;
                    };
                    let mut replacement = pool.alloc();
                    if replacement.len() < self.buf_size {
                        // Pool exhausted or shrunk: keep the bid off the ring
                        // (starvation is recoverable; re-arm refills lazily).
                        pool.free(replacement);
                        self.ring_starved_total += 1;
                        self.blocks[idx] = None;
                    } else {
                        let addr = replacement.as_mut_ptr();
                        self.blocks[idx] = Some(replacement);
                        self.refill.push((bid, addr));
                    }
                    completions.push(RecvCompletion {
                        data: Vec::new(),
                        block: Some(block),
                        len,
                        addr: None,
                    });
                } else {
                    let start = bid as usize * self.buf_size;
                    let data = self.bufs[start..start + len].to_vec();
                    completions.push(RecvCompletion { data, block: None, len, addr: None });
                    // SAFETY: contiguous backing for bid is unchanged.
                    let addr =
                        unsafe { Self::buffer_addr(&self.bufs, &self.blocks, self.buf_size, bid) };
                    if !addr.is_null() {
                        self.refill.push((bid, addr));
                    }
                }
            }
        }

        // Publish every staged refill with a single tail advance.
        let refill = std::mem::take(&mut self.refill);
        for (bid, addr) in refill {
            self.ring_add(bid, addr);
        }
        self.ring_advance();

        if self.rearm_pending {
            match self.arm_multishot() {
                Ok(()) => {}
                Err(error) => {
                    drain_error = drain_error.or(Some(error));
                }
            }
        } else if self.armed {
            // Flush the kernel CQ overflow list into the visible ring: when
            // the CQ filled up, the kernel parks further completions there -
            // including the terminating -ENOBUFS CQE - and only io_uring_enter
            // moves them. Without this the armed flag can report true while
            // the request already terminated invisibly.
            if let Some(ring) = self.ring.as_mut() {
                if let Err(error) = ring.submit() {
                    drain_error = drain_error.or(Some(error));
                }
            }
        }

        if let Some(error) = drain_error {
            return Err(error);
        }
        Ok(completions)
    }
}

impl Drop for UringRecvMultishot {
    fn drop(&mut self) {
        // Destroy the ring first: closing the io_uring fd unregisters the
        // provided-buffer ring and guarantees no pending kernel request can
        // reference the mapping or the backing buffers.
        drop(self.ring.take());

        if !self.ring_map.is_null() {
            // SAFETY: ring_map/map_len describe the mapping created in
            // new_inner and the io_uring ring is already destroyed.
            unsafe {
                libc::munmap(
                    self.ring_map as *mut libc::c_void,
                    self.ring_entries as usize * BUF_RING_ENTRY_BYTES,
                );
            }
            self.ring_map = std::ptr::null_mut();
        }
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
