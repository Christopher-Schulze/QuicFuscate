// io_uring batch UDP sender using the official `io-uring` crate.
//
// Replaces the old self-rolled libc::io_uring_setup/io_uring_enter code with
// proper batch submission: queued SendMsg SQEs, single submit_and_wait(queued),
// then reap all CQEs. This amortises the syscall overhead across the entire
// batch instead of doing one submit_and_wait(1) per packet.

use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::optimize::{AlignedBox, MemoryPool};
use io_uring::{opcode, types::CancelBuilder, IoUring, Probe};

/// Default submission queue depth (must be power of two).
const DEFAULT_QUEUE_DEPTH: u32 = 256;

/// Maximum number of packets admitted by one public sender call.
pub const MAX_BATCH_PACKETS: usize = DEFAULT_QUEUE_DEPTH as usize;
/// Maximum aggregate payload bytes admitted by one public sender call.
///
/// The bound matches the sender's normal per-slot warm capacity (2 KiB) across
/// the default 256 slots. Larger individual datagrams remain valid, but a
/// caller must not make the sender materialise an unbounded aggregate.
pub const MAX_BATCH_PAYLOAD_BYTES: usize = MAX_BATCH_PACKETS * 2048;
const BLOCKING_WORKER_OPERATION_TIMEOUT: Duration = Duration::from_millis(250);
const BLOCKING_WORKER_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// `IORING_CQE_F_NOTIF`: this is a buffer-release notification CQE (SendMsgZc ZC done).
const CQE_F_NOTIF: u32 = 1 << 3;
/// `IORING_CQE_F_MORE`: a SendMsgZc primary CQE has a follow-up notification.
const CQE_F_MORE: u32 = 1 << 1;

/// Batch UDP sender backed by a reusable io_uring instance.
///
/// A synchronous compatibility primitive for one owner and one send batch.
/// Runtime paths use `UringBatchWorker` below so the blocking completion
/// boundary is isolated from Tokio. If the kernel does not support io_uring
/// (old kernel, unprivileged container, etc.) construction returns `None` and
/// the caller falls through to `sendmmsg`.
///
/// `iovecs`, `msgs`, `sockaddrs`, and payload slots are retained at
/// `queue_depth` capacity after warm-up. Payloads are copied into those owned
/// slots before submission so kernel pointers never borrow the caller.
///
/// **SQPOLL**: constructed with `IORING_SETUP_SQPOLL` when the kernel
/// supports it (requires `CAP_SYS_ADMIN` on kernels < 5.12, unrestricted
/// since 5.12). Falls back to standard mode silently. Check `sqpoll_active()`.
///
/// **SendMsgZc**: experimental zero-copy send path (kernel 6.0+ for stability).
/// It is probed at startup but remains disabled unless
/// `QUICFUSCATE_IO_URING_ZC=1` is set. The production default is plain
/// `SendMsg`, because its CQE semantics are more portable across hosted CI,
/// containers, and mixed Linux kernels. Check `zc_supported()`.
///
/// Each input payload is copied into sender-owned storage before an SQE is
/// built. This preserves the kernel pointer contract if submission fails and
/// the caller immediately releases its input batch.
pub struct UringBatchSender {
    ring: IoUring,
    /// Sender-owned payload storage. SQE iovecs never point into caller memory.
    payloads: Vec<Vec<u8>>,
    /// Pre-allocated iovec scratch buffer (reused across batches).
    iovecs: Vec<libc::iovec>,
    /// Pre-allocated msghdr scratch buffer (reused across batches).
    msgs: Vec<libc::msghdr>,
    /// Pre-allocated sockaddr_storage for send_batch_to (unconnected sends).
    sockaddrs: Vec<libc::sockaddr_storage>,
    /// Pre-allocated completion bitmap for contiguous-prefix accounting.
    send_success: Vec<bool>,
    /// Completion bitmap separate from `send_success`, so an error CQE still
    /// counts as an observed completion and cannot leave a slot ambiguous.
    send_seen: Vec<bool>,
    /// Pre-allocated primary-CQE bitmap for SendMsgZc completion accounting.
    zc_primary_seen: Vec<bool>,
    /// Notification bitmap for SendMsgZc buffer-release CQEs.
    zc_notification_seen: Vec<bool>,
    /// Notification expectation bitmap. The kernel sets `CQE_F_MORE` on the
    /// primary CQE when a release notification will follow, including for an
    /// errored request that still retains the buffer.
    zc_notification_expected: Vec<bool>,
    /// True when the ring was constructed with SQPOLL mode.
    sqpoll_active: bool,
    /// True when SendMsgZc was probed successfully and explicitly enabled.
    zc_supported: bool,
    /// Set after a submit/protocol error. The sender is then quarantined so
    /// its raw-pointer scratch storage can never be reused while an accepted
    /// SQE might still reference it.
    submission_poisoned: bool,
}

// SAFETY: UringBatchSender owns its ring, payloads, and all scratch storage.
// Raw pointers inside msghdr/iovec entries are rebuilt only through exclusive
// &mut self methods. The type is moved between threads, never concurrently
// accessed through shared references, and a failed submission quarantines the
// storage before another batch can rebuild it.
unsafe impl Send for UringBatchSender {}

/// Disposition of one packet in a completed io_uring batch.
///
/// `Failed` and `NotSubmitted` are safe fallback candidates. `Quarantined`
/// means that submission or completion ownership could not be proven after a
/// protocol error; the caller must not retry it because the kernel may already
/// have accepted the datagram. Keeping this distinction explicit prevents a
/// count-only fallback from duplicating an out-of-order successful CQE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchSendDisposition {
    Sent,
    Failed,
    NotSubmitted,
    Quarantined,
}

/// Exact per-input disposition returned by a successful batch operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSendResult {
    dispositions: Vec<BatchSendDisposition>,
}

impl BatchSendResult {
    fn not_submitted(len: usize) -> Self {
        Self { dispositions: vec![BatchSendDisposition::NotSubmitted; len] }
    }

    fn from_chunk(dispositions: Vec<BatchSendDisposition>) -> Self {
        Self { dispositions }
    }

    /// Number of input packets represented by this result.
    pub fn len(&self) -> usize {
        self.dispositions.len()
    }

    /// Whether this result represents an empty input batch.
    pub fn is_empty(&self) -> bool {
        self.dispositions.is_empty()
    }

    /// Whether the input packet at `index` was accepted as a complete send.
    pub fn is_sent(&self, index: usize) -> bool {
        self.dispositions.get(index) == Some(&BatchSendDisposition::Sent)
    }

    /// Exact disposition for one input packet.
    pub fn disposition(&self, index: usize) -> Option<BatchSendDisposition> {
        self.dispositions.get(index).copied()
    }

    /// Number of packets accepted as complete sends.
    pub fn sent_count(&self) -> usize {
        self.dispositions.iter().filter(|status| **status == BatchSendDisposition::Sent).count()
    }

    fn set_chunk(&mut self, start: usize, chunk: &[BatchSendDisposition]) {
        let end = start.saturating_add(chunk.len());
        if end <= self.dispositions.len() {
            self.dispositions[start..end].copy_from_slice(chunk);
        }
    }

    fn with_chunk_error(
        &self,
        start: usize,
        chunk: &BatchSendResult,
        error: std::io::Error,
    ) -> BatchSendError {
        let mut disposition = self.clone();
        disposition.set_chunk(start, &chunk.dispositions);
        BatchSendError { error, disposition }
    }
}

/// Error carrying the exact disposition known before a batch was quarantined.
#[derive(Debug)]
pub struct BatchSendError {
    error: std::io::Error,
    disposition: BatchSendResult,
}

impl BatchSendError {
    fn not_submitted(error: std::io::Error, len: usize) -> Self {
        Self { error, disposition: BatchSendResult::not_submitted(len) }
    }

    fn quarantined(error: std::io::Error, queued: usize) -> Self {
        let mut disposition = BatchSendResult::not_submitted(queued);
        disposition.dispositions.fill(BatchSendDisposition::Quarantined);
        Self { error, disposition }
    }

    /// Exact disposition retained at the failure boundary.
    pub fn disposition(&self) -> &BatchSendResult {
        &self.disposition
    }

    /// I/O kind of the underlying failure for compatibility fallback policy.
    pub fn kind(&self) -> std::io::ErrorKind {
        self.error.kind()
    }

    /// Convert to the legacy I/O error surface while retaining the fail-closed
    /// no-retry policy in the detailed API.
    pub fn into_io_error(self) -> std::io::Error {
        self.error
    }
}

impl std::fmt::Display for BatchSendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for BatchSendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

struct SubmitOutcome {
    queued: usize,
    dispositions: BatchSendResult,
}

struct SendControl<'a> {
    shutdown: &'a AtomicBool,
    deadline: Instant,
}

struct IovecFailureInjection<'a> {
    #[cfg(feature = "rust-tests")]
    invalid_slots: Option<&'a [usize]>,
    #[cfg(not(feature = "rust-tests"))]
    _lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> IovecFailureInjection<'a> {
    #[inline(always)]
    fn none() -> Self {
        Self {
            #[cfg(feature = "rust-tests")]
            invalid_slots: None,
            #[cfg(not(feature = "rust-tests"))]
            _lifetime: std::marker::PhantomData,
        }
    }

    #[cfg(feature = "rust-tests")]
    #[inline]
    fn invalid_slots(failed_slots: &'a [usize]) -> Self {
        Self { invalid_slots: Some(failed_slots) }
    }

    #[inline(always)]
    fn validate(&self, input_len: usize) -> std::io::Result<()> {
        #[cfg(feature = "rust-tests")]
        if let Some(failed_slots) = self.invalid_slots {
            return validate_injected_failure_slots(input_len, failed_slots);
        }
        #[cfg(not(feature = "rust-tests"))]
        let _ = input_len;
        Ok(())
    }

    #[inline(always)]
    fn apply(&self, msgs: &mut [libc::msghdr]) {
        #[cfg(feature = "rust-tests")]
        if let Some(failed_slots) = self.invalid_slots {
            inject_invalid_iovec_slots(msgs, failed_slots);
        }
        #[cfg(not(feature = "rust-tests"))]
        let _ = msgs;
    }
}

impl UringBatchSender {
    /// Try to create a sender with the given queue depth.
    ///
    /// Attempts SQPOLL mode first (eliminates `io_uring_enter` syscalls during
    /// steady-state operation at the cost of a kernel polling thread).
    /// Falls back to standard mode on `EPERM` or unsupported kernels.
    /// Probes `SendMsgZc` support via `io_uring::Probe`; activation still
    /// requires `QUICFUSCATE_IO_URING_ZC=1`.
    ///
    /// Returns `None` when io_uring cannot be initialised (kernel too old,
    /// seccomp filter, missing permissions, etc.).
    pub fn new(queue_depth: u32) -> Option<Self> {
        Self::new_inner(queue_depth, true)
    }

    /// Construct the standard `SendMsg` path even when the process opted in
    /// to `SendMsgZc`.
    ///
    /// This rust-tests-only constructor makes the native partial-send proof
    /// independent of process-global environment state.
    #[cfg(feature = "rust-tests")]
    pub fn new_for_sendmsg_proof(queue_depth: u32) -> Option<Self> {
        Self::new_inner(queue_depth, false)
    }

    fn new_inner(queue_depth: u32, allow_zc: bool) -> Option<Self> {
        let depth = queue_depth.max(4).checked_next_power_of_two()?;
        let environment = crate::env_utils::EnvSnapshot::capture();

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

        // Probe SendMsgZc support, but keep the path explicit opt-in. Kernel
        // completion ordering for SendMsgZc is still less portable than plain
        // SendMsg across hosted CI and containerized Linux environments; the
        // stable production default must never risk blocking a sender batch.
        let zc_probe_supported = {
            let mut probe = Probe::new();
            ring.submitter().register_probe(&mut probe).is_ok()
                && probe.is_supported(opcode::SendMsgZc::CODE)
        };
        let zc_opt_in = environment.flag("QUICFUSCATE_IO_URING_ZC", false);
        let zc_supported = allow_zc && zc_probe_supported && zc_opt_in;

        if sqpoll_active {
            crate::telemetry::IO_URING_SQPOLL_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
        }
        if zc_supported {
            log::debug!("io_uring SendMsgZc (zero-copy) supported");
        } else if zc_probe_supported {
            log::debug!("io_uring SendMsgZc available but disabled; set QUICFUSCATE_IO_URING_ZC=1 to opt in");
        }

        let cap = depth as usize;
        Some(Self {
            ring,
            payloads: Vec::with_capacity(cap),
            // Pre-allocate scratch buffers to queue depth so the hot path
            // never touches the allocator.
            iovecs: Vec::with_capacity(cap),
            msgs: Vec::with_capacity(cap),
            sockaddrs: Vec::with_capacity(cap),
            send_success: Vec::with_capacity(cap),
            send_seen: Vec::with_capacity(cap),
            zc_primary_seen: Vec::with_capacity(cap),
            zc_notification_seen: Vec::with_capacity(cap),
            zc_notification_expected: Vec::with_capacity(cap),
            sqpoll_active,
            zc_supported,
            submission_poisoned: false,
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

    /// True when zero-copy `SendMsgZc` was probed and explicitly enabled.
    #[inline]
    pub fn zc_supported(&self) -> bool {
        self.zc_supported
    }

    fn ensure_usable(&self) -> std::io::Result<()> {
        if self.submission_poisoned {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "io_uring sender is quarantined after a submission failure",
            ));
        }
        Ok(())
    }

    fn prepare_payload_slots(&mut self, count: usize) {
        debug_assert!(count <= MAX_BATCH_PACKETS);
        self.payloads.truncate(count);
        self.payloads.resize_with(count, || Vec::with_capacity(2048));
    }

    fn validate_batch_admission(count: usize, payload_bytes: usize) -> std::io::Result<()> {
        if count > MAX_BATCH_PACKETS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("io_uring batch admits at most {MAX_BATCH_PACKETS} packets, got {count}"),
            ));
        }
        if payload_bytes > MAX_BATCH_PAYLOAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "io_uring batch admits at most {MAX_BATCH_PAYLOAD_BYTES} payload bytes, got {payload_bytes}"
                ),
            ));
        }
        Ok(())
    }

    fn checked_payload_bytes<'a, I>(mut payloads: I) -> std::io::Result<usize>
    where
        I: Iterator<Item = &'a [u8]>,
    {
        payloads.try_fold(0usize, |total, payload| {
            total.checked_add(payload.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "io_uring batch payload byte count overflow",
                )
            })
        })
    }

    fn quarantine(&mut self, error: std::io::Error) -> std::io::Error {
        self.submission_poisoned = true;

        // `register_sync_cancel` is available on newer Linux kernels and is
        // deliberately used only on the exceptional path. It synchronously
        // cancels requests already accepted by the kernel. Requests still in
        // the SQ are retained in this poisoned sender and are never reused.
        if let Err(cancel_error) =
            self.ring.submitter().register_sync_cancel(None, CancelBuilder::any())
        {
            log::debug!("io_uring sender cancellation after failure unavailable: {cancel_error}");
        }
        {
            let cq = self.ring.completion();
            for _ in cq {}
        }

        std::io::Error::new(
            error.kind(),
            format!("io_uring sender quarantined after submission failure: {error}"),
        )
    }

    fn submit_and_wait(&mut self, want: usize) -> std::io::Result<usize> {
        match self.ring.submit_and_wait(want) {
            Ok(submitted) => Ok(submitted),
            Err(error) => Err(self.quarantine(error)),
        }
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
        self.send_batch_with_disposition(fd, payloads)
            .map(|result| result.sent_count())
            .map_err(BatchSendError::into_io_error)
    }

    /// Submit a connected-socket batch with exact per-input dispositions.
    pub fn send_batch_with_disposition(
        &mut self,
        fd: RawFd,
        payloads: &[&[u8]],
    ) -> Result<BatchSendResult, BatchSendError> {
        self.send_batch_with_wait(fd, payloads, None, IovecFailureInjection::none())
    }

    /// Submit a connected-socket batch while making selected `msghdr` iovec
    /// pointers invalid before kernel submission.
    ///
    /// This rust-tests-only boundary drives real Linux `SendMsg` or
    /// `SendMsgZc` CQEs with deterministic per-slot `EFAULT` results. It is
    /// used to prove that a later successful datagram is never retried after
    /// an injected middle-slot failure.
    #[cfg(feature = "rust-tests")]
    pub fn send_batch_with_injected_iovec_failures(
        &mut self,
        fd: RawFd,
        payloads: &[&[u8]],
        failed_slots: &[usize],
    ) -> Result<BatchSendResult, BatchSendError> {
        self.send_batch_with_wait(
            fd,
            payloads,
            None,
            IovecFailureInjection::invalid_slots(failed_slots),
        )
    }

    fn send_batch_with_wait(
        &mut self,
        fd: RawFd,
        payloads: &[&[u8]],
        control: Option<&SendControl<'_>>,
        failure_injection: IovecFailureInjection<'_>,
    ) -> Result<BatchSendResult, BatchSendError> {
        let input_len = payloads.len();
        if let Err(error) = self.ensure_usable() {
            return Err(BatchSendError::quarantined(error, input_len));
        }
        if payloads.is_empty() {
            return Ok(BatchSendResult::not_submitted(0));
        }
        if control.is_some() && self.zc_supported {
            return Err(BatchSendError::not_submitted(
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "controlled io_uring sends do not permit SendMsgZc notification ownership",
                ),
                input_len,
            ));
        }
        let payload_bytes = Self::checked_payload_bytes(payloads.iter().copied())
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        Self::validate_batch_admission(payloads.len(), payload_bytes)
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        failure_injection
            .validate(input_len)
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;

        // Keep every kernel-visible payload alive inside the sender. This is
        // required for the submit-error quarantine and for SendMsgZc's later
        // notification CQE; caller-owned slices may be released on return.
        self.prepare_payload_slots(payloads.len());
        for (slot, payload) in self.payloads.iter_mut().zip(payloads.iter().copied()) {
            slot.clear();
            slot.extend_from_slice(payload);
        }

        // Reuse pre-allocated scratch buffers after the payload ownership
        // boundary has been established.
        self.iovecs.clear();
        self.msgs.clear();

        for payload in &self.payloads {
            // SAFETY: libc::iovec uses a mutable pointer for the C ABI, but
            // sendmsg/sendmsg_zc read from this region and do not write it.
            self.iovecs.push(libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            });
        }
        for iov in &mut self.iovecs {
            // SAFETY: msghdr is fully zeroed; msg_iov points into self.iovecs,
            // which lives for the duration of this call. The referenced iovec
            // points into sender-owned payload storage and remains valid until
            // all completions are reaped below.
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_iov = iov as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            self.msgs.push(hdr);
        }
        failure_injection.apply(&mut self.msgs);

        let sq_cap = self.ring.params().sq_entries() as usize;
        let mut result = BatchSendResult::not_submitted(input_len);

        if self.zc_supported {
            // Zero-copy path: SendMsgZc with dual-CQE drain.
            let mut chunk_start = 0usize;
            while chunk_start < self.msgs.len() {
                let chunk_end = (chunk_start + sq_cap).min(self.msgs.len());
                let outcome = match self.submit_chunk_zc(fd, chunk_start, chunk_end - chunk_start) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        let BatchSendError { error: io_error, disposition } = error;
                        return Err(result.with_chunk_error(chunk_start, &disposition, io_error));
                    }
                };
                chunk_start += outcome.queued;
                result.set_chunk(chunk_start - outcome.queued, &outcome.dispositions.dispositions);
                if outcome.dispositions.sent_count() < outcome.queued {
                    return Ok(result);
                }
            }
        } else {
            // Standard path: SendMsg with single CQE per SQE.
            let mut chunk_start = 0usize;
            while chunk_start < self.msgs.len() {
                let chunk_end = (chunk_start + sq_cap).min(self.msgs.len());
                let outcome =
                    match self.submit_chunk(fd, chunk_start, chunk_end - chunk_start, control) {
                        Ok(outcome) => outcome,
                        Err(error) => {
                            let BatchSendError { error: io_error, disposition } = error;
                            return Err(result.with_chunk_error(
                                chunk_start,
                                &disposition,
                                io_error,
                            ));
                        }
                    };
                chunk_start += outcome.queued;
                result.set_chunk(chunk_start - outcome.queued, &outcome.dispositions.dispositions);
                if outcome.dispositions.sent_count() < outcome.queued {
                    return Ok(result);
                }
            }
        }

        Ok(result)
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
        self.send_batch_to_with_disposition(fd, packets)
            .map(|result| result.sent_count())
            .map_err(BatchSendError::into_io_error)
    }

    /// Submit an unconnected-socket batch with exact per-input dispositions.
    pub fn send_batch_to_with_disposition(
        &mut self,
        fd: RawFd,
        packets: &[(SocketAddr, &[u8])],
    ) -> Result<BatchSendResult, BatchSendError> {
        self.send_batch_to_with_wait(fd, packets, None, IovecFailureInjection::none())
    }

    /// Submit an unconnected-socket batch with deterministic kernel `EFAULT`
    /// results for selected iovec slots.
    ///
    /// The method exists only with `rust-tests` and exercises the same
    /// `SendMsg` implementation as the server runtime path.
    #[cfg(feature = "rust-tests")]
    pub fn send_batch_to_with_injected_iovec_failures(
        &mut self,
        fd: RawFd,
        packets: &[(SocketAddr, &[u8])],
        failed_slots: &[usize],
    ) -> Result<BatchSendResult, BatchSendError> {
        self.send_batch_to_with_wait(
            fd,
            packets,
            None,
            IovecFailureInjection::invalid_slots(failed_slots),
        )
    }

    fn send_batch_to_with_wait(
        &mut self,
        fd: RawFd,
        packets: &[(SocketAddr, &[u8])],
        control: Option<&SendControl<'_>>,
        failure_injection: IovecFailureInjection<'_>,
    ) -> Result<BatchSendResult, BatchSendError> {
        let input_len = packets.len();
        if let Err(error) = self.ensure_usable() {
            return Err(BatchSendError::quarantined(error, input_len));
        }
        if packets.is_empty() {
            return Ok(BatchSendResult::not_submitted(0));
        }
        if control.is_some() && self.zc_supported {
            return Err(BatchSendError::not_submitted(
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "controlled io_uring sends do not permit SendMsgZc notification ownership",
                ),
                input_len,
            ));
        }
        let payload_bytes =
            Self::checked_payload_bytes(packets.iter().map(|(_, payload)| *payload))
                .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        Self::validate_batch_admission(packets.len(), payload_bytes)
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;
        failure_injection
            .validate(input_len)
            .map_err(|error| BatchSendError::not_submitted(error, input_len))?;

        // Copy payloads into sender-owned slots before any raw pointer is
        // published to io_uring. The input staging vector can be dropped as
        // soon as this method returns, including on a submit failure.
        self.prepare_payload_slots(packets.len());
        for (slot, (_, payload)) in self.payloads.iter_mut().zip(packets.iter()) {
            slot.clear();
            slot.extend_from_slice(payload);
        }

        self.iovecs.clear();
        self.msgs.clear();
        self.sockaddrs.clear();

        // Pass 1: build iovecs (stable base for msg_iov pointers).
        for payload in &self.payloads {
            // SAFETY: libc::iovec uses a mutable pointer for the C ABI, but
            // sendmsg reads this owned payload and does not mutate it.
            self.iovecs.push(libc::iovec {
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            });
        }

        // Pass 2: fill sockaddr_storage per destination (stable for msg_name).
        for (addr, _) in packets {
            // SAFETY: sockaddr_storage is POD; zeroed init is valid.
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            fill_sockaddr(*addr, &mut storage);
            self.sockaddrs.push(storage);
        }

        // Pass 3: build msghdrs with stable pointers into iovecs and sockaddrs.
        // Both vecs are fully populated above - no further pushes, so no realloc.
        for (i, (addr, _)) in packets.iter().enumerate() {
            // SAFETY: iovecs[i] and sockaddrs[i] are valid for the lifetime of
            // this call and the Vecs will not reallocate after this point.
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_iov = &mut self.iovecs[i] as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            hdr.msg_name = &mut self.sockaddrs[i] as *mut _ as *mut libc::c_void;
            hdr.msg_namelen = addr_len(*addr);
            self.msgs.push(hdr);
        }
        failure_injection.apply(&mut self.msgs);

        let sq_cap = self.ring.params().sq_entries() as usize;
        let mut result = BatchSendResult::not_submitted(input_len);

        let mut chunk_start = 0usize;
        while chunk_start < self.msgs.len() {
            let chunk_end = (chunk_start + sq_cap).min(self.msgs.len());
            let outcome = match self.submit_chunk(fd, chunk_start, chunk_end - chunk_start, control)
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    let BatchSendError { error: io_error, disposition } = error;
                    return Err(result.with_chunk_error(chunk_start, &disposition, io_error));
                }
            };
            chunk_start += outcome.queued;
            result.set_chunk(chunk_start - outcome.queued, &outcome.dispositions.dispositions);
            if outcome.dispositions.sent_count() < outcome.queued {
                crate::telemetry::IO_URING_SERVER_PACKETS.inc_by(result.sent_count() as u64);
                return Ok(result);
            }
        }

        crate::telemetry::IO_URING_SERVER_PACKETS.inc_by(result.sent_count() as u64);
        Ok(result)
    }

    /// Push one chunk of SendMsg SQEs (by index range into `self.msgs`) and reap completions.
    fn submit_chunk(
        &mut self,
        fd: RawFd,
        start: usize,
        count: usize,
        control: Option<&SendControl<'_>>,
    ) -> Result<SubmitOutcome, BatchSendError> {
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
                // SAFETY: msghdr and its iovec point into sender-owned storage.
                // They remain stable until every completion for this chunk is
                // observed, including the failure/quarantine path.
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
            return Err(BatchSendError::not_submitted(
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "io_uring submission queue accepted no SendMsg SQEs",
                ),
                0,
            ));
        }

        // The public compatibility API uses one blocking submit-and-wait. The
        // runtime-owned worker uses a submit-and-poll boundary so shutdown and
        // the operation deadline remain observable without blocking Tokio.
        if let Some(control) = control {
            if let Err(error) = self.submit_and_poll(queued, control) {
                return Err(BatchSendError::quarantined(error, queued));
            }
        } else {
            if let Err(error) = self.submit_and_wait(queued) {
                return Err(BatchSendError::quarantined(error, queued));
            }
        }
        crate::telemetry::IO_URING_SUBMIT_CALLS.inc();

        // Reap completions. An error CQE is still a completion and must be
        // counted before the scratch storage can be reused. Any missing,
        // duplicate, out-of-range, or overflowed CQE poisons the sender.
        self.send_success.clear();
        self.send_success.resize(queued, false);
        self.send_seen.clear();
        self.send_seen.resize(queued, false);
        let mut completion_error = None;
        let mut completion_count = 0usize;
        let overflow;
        {
            let cq = self.ring.completion();
            overflow = cq.overflow();
            for cqe in cq {
                let idx = match checked_slot_index(cqe.user_data(), queued) {
                    Ok(idx) => idx,
                    Err(error) => {
                        completion_error = Some(error.to_string());
                        continue;
                    }
                };
                if self.send_seen[idx] {
                    completion_error = Some(format!("duplicate SendMsg CQE for slot {idx}"));
                    continue;
                }
                self.send_seen[idx] = true;
                completion_count += 1;
                if cqe.result() >= 0 {
                    self.send_success[idx] = true;
                } else {
                    log::trace!(
                        "io_uring SendMsg CQE error: user_data={} result={}",
                        cqe.user_data(),
                        cqe.result()
                    );
                }
            }
        }
        if let Some(error) = completion_error {
            return Err(BatchSendError::quarantined(
                self.quarantine(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                queued,
            ));
        }
        if overflow != 0 || completion_count != queued {
            return Err(BatchSendError::quarantined(
                self.quarantine(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "io_uring SendMsg completion set incomplete: {completion_count}/{queued}, cq_overflow={overflow}"
                    ),
                )),
                queued,
            ));
        }
        let dispositions = BatchSendResult::from_chunk(
            self.send_seen
                .iter()
                .zip(self.send_success.iter())
                .map(|(seen, success)| match (*seen, *success) {
                    (true, true) => BatchSendDisposition::Sent,
                    (true, false) => BatchSendDisposition::Failed,
                    (false, _) => BatchSendDisposition::Quarantined,
                })
                .collect(),
        );

        Ok(SubmitOutcome { queued, dispositions })
    }

    fn submit_and_poll(&mut self, queued: usize, control: &SendControl<'_>) -> std::io::Result<()> {
        self.ring.submit().map_err(|error| self.quarantine(error))?;
        loop {
            // `CompletionQueue` is an iterator: `count()` would consume and
            // acknowledge every ready CQE before the reap boundary below.
            if self.ring.completion().len() >= queued {
                return Ok(());
            }
            if control.shutdown.load(Ordering::Acquire) {
                return Err(self.quarantine(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "io_uring blocking worker shutdown requested",
                )));
            }
            if Instant::now() >= control.deadline {
                return Err(self.quarantine(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "io_uring batch completion deadline exceeded",
                )));
            }
            self.ring.submit().map_err(|error| self.quarantine(error))?;
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Push one chunk of `SendMsgZc` SQEs and reap primary + notification CQEs.
    ///
    /// Each `SendMsgZc` SQE may generate one or two CQEs:
    /// - **Primary**: data accepted into the socket buffer.
    /// - **Notification** (`CQE_F_NOTIF` set): kernel released the buffer,
    ///   announced by `CQE_F_MORE` on the primary CQE.
    ///
    /// We call `submit_and_wait(queued)` to submit the SQEs, then keep draining
    /// until every queued SQE has produced its primary CQE and every primary
    /// carrying `CQE_F_MORE` has produced its notification CQE. This keeps
    /// sender-owned payloads valid through the complete SendMsgZc lifetime
    /// before the next batch can rebuild the scratch pointers.
    fn submit_chunk_zc(
        &mut self,
        fd: RawFd,
        start: usize,
        count: usize,
    ) -> Result<SubmitOutcome, BatchSendError> {
        let fd_typed = io_uring::types::Fd(fd);

        // No CQE from a previous ZC chunk may remain: a notification exists
        // only when its primary CQE announced `CQE_F_MORE`, and this method
        // waits for every such notification before returning. A stale CQE
        // therefore indicates a broken completion accounting boundary.
        let stale_cqes = {
            let cq = self.ring.completion();
            cq.count()
        };
        if stale_cqes != 0 {
            return Err(BatchSendError::quarantined(
                self.quarantine(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("io_uring SendMsgZc found {stale_cqes} stale CQEs before submission"),
                )),
                count,
            ));
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
                // SAFETY: msghdr and its iovec point into sender-owned storage.
                // They remain valid until both primary and notification CQEs
                // have been observed.
                unsafe {
                    if sq.push(&entry).is_err() {
                        break;
                    }
                }
                queued += 1;
            }
        }
        if queued == 0 {
            return Err(BatchSendError::not_submitted(
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "io_uring submission queue accepted no SendMsgZc SQEs",
                ),
                0,
            ));
        }

        // Wait for at least `queued` CQEs to kick the batch, then keep waiting
        // until all primary send CQEs have been observed. SendMsgZc completion
        // ordering is kernel-dependent: notification CQEs can satisfy the first
        // wait without proving that every packet in this chunk was accepted.
        if let Err(error) = self.submit_and_wait(queued) {
            return Err(BatchSendError::quarantined(error, queued));
        }
        crate::telemetry::IO_URING_SUBMIT_CALLS.inc();

        self.send_success.clear();
        self.send_success.resize(queued, false);
        self.zc_primary_seen.clear();
        self.zc_primary_seen.resize(queued, false);
        self.zc_notification_seen.clear();
        self.zc_notification_seen.resize(queued, false);
        self.zc_notification_expected.clear();
        self.zc_notification_expected.resize(queued, false);
        let mut primary_seen_count = 0usize;
        loop {
            let notifications_complete = self
                .zc_notification_expected
                .iter()
                .zip(self.zc_notification_seen.iter())
                .all(|(expected, seen)| !*expected || *seen);
            if primary_seen_count == queued && notifications_complete {
                break;
            }

            let mut drained = 0usize;
            let mut completion_error = None;
            let overflow;
            {
                let cq = self.ring.completion();
                overflow = cq.overflow();
                for cqe in cq {
                    drained += 1;
                    let idx = match checked_slot_index(cqe.user_data(), queued) {
                        Ok(idx) => idx,
                        Err(error) => {
                            completion_error = Some(error.to_string());
                            continue;
                        }
                    };
                    if cqe.flags() & CQE_F_NOTIF != 0 {
                        if self.zc_notification_seen[idx] {
                            completion_error =
                                Some(format!("duplicate SendMsgZc notification for slot {idx}"));
                            continue;
                        }
                        self.zc_notification_seen[idx] = true;
                        if self.zc_primary_seen[idx] && !self.zc_notification_expected[idx] {
                            completion_error =
                                Some(format!("unexpected SendMsgZc notification for slot {idx}"));
                        }
                        crate::telemetry::IO_URING_ZC_NOTIFS.inc();
                        continue;
                    }

                    if self.zc_primary_seen[idx] {
                        completion_error =
                            Some(format!("duplicate SendMsgZc primary CQE for slot {idx}"));
                        continue;
                    }
                    self.zc_primary_seen[idx] = true;
                    primary_seen_count += 1;
                    self.zc_notification_expected[idx] = cqe.flags() & CQE_F_MORE != 0;
                    if cqe.result() >= 0 {
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
            if let Some(error) = completion_error {
                return Err(BatchSendError::quarantined(
                    self.quarantine(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
                    queued,
                ));
            }
            if overflow != 0 {
                return Err(BatchSendError::quarantined(
                    self.quarantine(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("io_uring SendMsgZc CQ overflow: {overflow}"),
                    )),
                    queued,
                ));
            }
            if primary_seen_count == queued
                && self
                    .zc_notification_seen
                    .iter()
                    .zip(self.zc_notification_expected.iter())
                    .any(|(seen, expected)| *seen && !*expected)
            {
                return Err(BatchSendError::quarantined(
                    self.quarantine(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "io_uring SendMsgZc produced an unannounced notification",
                    )),
                    queued,
                ));
            }
            let notifications_complete = self
                .zc_notification_expected
                .iter()
                .zip(self.zc_notification_seen.iter())
                .all(|(expected, seen)| !*expected || *seen);
            if (primary_seen_count < queued || !notifications_complete) && drained == 0 {
                if let Err(error) = self.submit_and_wait(1) {
                    return Err(BatchSendError::quarantined(error, queued));
                }
            }
        }

        let dispositions = BatchSendResult::from_chunk(
            self.zc_primary_seen
                .iter()
                .zip(self.send_success.iter())
                .map(|(seen, success)| match (*seen, *success) {
                    (true, true) => BatchSendDisposition::Sent,
                    (true, false) => BatchSendDisposition::Failed,
                    (false, _) => BatchSendDisposition::Quarantined,
                })
                .collect(),
        );

        Ok(SubmitOutcome { queued, dispositions })
    }
}

impl Drop for UringBatchSender {
    fn drop(&mut self) {
        if !self.submission_poisoned {
            return;
        }

        let canceled =
            self.ring.submitter().register_sync_cancel(None, CancelBuilder::any()).is_ok();
        {
            let cq = self.ring.completion();
            for _ in cq {}
        }
        let pending_sqes = {
            let sq = self.ring.submission();
            !sq.is_empty()
        };
        if canceled && !pending_sqes {
            return;
        }

        // A kernel without synchronous cancellation support may still own an
        // accepted pointer when the sender is dropped. Leak only the poisoned
        // pointer-bearing storage; this is a fail-closed safety boundary, not
        // a normal-path allocation policy. The ring is then dropped without a
        // dangling userspace pointer.
        std::mem::forget(std::mem::take(&mut self.payloads));
        std::mem::forget(std::mem::take(&mut self.iovecs));
        std::mem::forget(std::mem::take(&mut self.msgs));
        std::mem::forget(std::mem::take(&mut self.sockaddrs));
    }
}

mod worker;
pub use worker::UringBatchWorker;
mod recv;
pub use recv::{RecvCompletion, UringRecvBatch};

fn checked_slot_index(user_data: u64, depth: usize) -> std::io::Result<usize> {
    let idx = usize::try_from(user_data).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("io_uring completion user_data does not fit usize: {user_data}"),
        )
    })?;
    if idx >= depth {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("io_uring completion slot out of range: {idx}/{depth}"),
        ));
    }
    Ok(idx)
}

#[cfg(feature = "rust-tests")]
fn validate_injected_failure_slots(
    input_len: usize,
    failed_slots: &[usize],
) -> std::io::Result<()> {
    if failed_slots.is_empty() {
        return Ok(());
    }
    let mut seen = vec![false; input_len];
    for &index in failed_slots {
        let Some(slot_seen) = seen.get_mut(index) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("injected io_uring failure slot out of range: {index}/{input_len}"),
            ));
        };
        if *slot_seen {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("duplicate injected io_uring failure slot: {index}"),
            ));
        }
        *slot_seen = true;
    }
    Ok(())
}

#[cfg(feature = "rust-tests")]
fn inject_invalid_iovec_slots(msgs: &mut [libc::msghdr], failed_slots: &[usize]) {
    for &index in failed_slots {
        msgs[index].msg_iov = std::ptr::null_mut();
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
            // SAFETY: sockaddr_storage is large enough to hold sockaddr_in.
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
            // SAFETY: sockaddr_storage is large enough to hold sockaddr_in6.
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

// Synchronous compatibility owner for callers outside the runtime-owned async
// server path. The canonical server flush path receives `UringBatchWorker`
// explicitly. The `RefCell` borrow is never held across await points because
// this compatibility helper is fully synchronous.
thread_local! {
    static SERVER_URING_SENDER: std::cell::RefCell<Option<UringBatchSender>> =
        std::cell::RefCell::new(UringBatchSender::with_defaults());
}

/// Send a batch of `(addr, payload)` pairs on an **unconnected** server UDP
/// socket via the thread-local synchronous compatibility sender.
///
/// Returns `Some(sent_count)` when at least one packet was sent, `None` when
/// io_uring is unavailable or no progress was made.
pub fn server_send_batch_to(fd: RawFd, packets: &[(SocketAddr, &[u8])]) -> Option<usize> {
    server_send_batch_to_with_disposition(fd, packets).map(|result| result.sent_count())
}

/// Send a server batch through the synchronous compatibility sender while
/// preserving exact per-input ownership for callers that need a fallback.
pub fn server_send_batch_to_with_disposition(
    fd: RawFd,
    packets: &[(SocketAddr, &[u8])],
) -> Option<BatchSendResult> {
    SERVER_URING_SENDER.with(|cell| {
        let mut guard = cell.borrow_mut();
        if let Some(ref mut sender) = *guard {
            match sender.send_batch_to_with_disposition(fd, packets) {
                Ok(result) if result.sent_count() > 0 => {
                    crate::telemetry::IO_URING_SERVER_SUBMIT_CALLS.inc();
                    Some(result)
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
/// Parse a `libc::sockaddr_storage` into a `std::net::SocketAddr`.
/// Returns `None` if the address family is unrecognized.
fn parse_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    match storage.ss_family as i32 {
        libc::AF_INET => {
            let sa = storage as *const _ as *const libc::sockaddr_in;
            // SAFETY: storage is a valid sockaddr_storage that was filled by
            // fill_sockaddr with AF_INET, so casting to sockaddr_in is valid and
            // the pointer is dereferenceable for the size of sockaddr_in.
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
            // SAFETY: storage is a valid sockaddr_storage that was filled by
            // fill_sockaddr with AF_INET6, so casting to sockaddr_in6 is valid
            // and the pointer is dereferenceable for the size of sockaddr_in6.
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
mod tests;
