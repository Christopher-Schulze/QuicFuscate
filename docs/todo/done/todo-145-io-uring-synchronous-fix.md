# TODO-145: io_uring submit_and_wait Blocks Per-Packet, Defeating Batching

## Status
**IMPLEMENTED** - IoUringDatagram send paths converted from blocking submit_and_wait(1) per
packet to non-blocking submit() + opportunistic CQE drain. Module-level documentation added
clarifying architecture, feature gate status, and the fact that the uring_sys feature has no
io_uring crate dependency declared (so it cannot currently compile). The production Linux
fast path remains sendmmsg in udpfast.rs. See commit for details.

NOTE: xdp.rs still has the same submit_and_wait(1) anti-pattern in three places (send, recv,
multishot recv). That code is also behind feature = "uring_sys" and equally non-compilable.
A future TODO should address xdp.rs if/when the uring_sys feature is actually wired up.

## Severity
**HIGH**

## Context
In `src/transport/uring.rs:92`, `submit_and_wait(1)` is called for every individual packet send operation. This call:

1. Submits the SQE (submission queue entry) to the kernel
2. Blocks the calling thread until at least 1 CQE (completion queue entry) is available
3. Returns only after the kernel has processed the submission

This completely defeats the purpose of io_uring, which is designed for:
- Batching multiple submissions before a single `submit()` call
- Asynchronous completion harvesting from the CQ ring
- Zero-syscall operation via SQPOLL mode
- Amortizing syscall overhead across many I/O operations

The current implementation is effectively equivalent to (or slower than) a simple `sendto()` syscall, because:
- Each packet incurs a full syscall via `submit_and_wait`
- The thread blocks waiting for completion (no async benefit)
- No batching of multiple packets into a single submission
- The mutex (see TODO-135) adds contention on top

## Root Cause
io_uring was implemented with synchronous semantics (submit-and-wait per packet) instead of the intended asynchronous batch model.

## Fix Plan
**Option A - Implement proper async io_uring:**
1. Accumulate SQEs in the submission ring without submitting
2. Submit batch when:
   - Ring is full (or near full)
   - A configurable batch size is reached (e.g., 32 packets)
   - A configurable time deadline expires (e.g., 100us)
   - Explicit flush is requested
3. Harvest CQEs from completion ring asynchronously:
   - Use epoll/io_uring's eventfd notification for completion
   - Process completions in a dedicated async task
   - Handle errors/retries per-CQE
4. Consider SQPOLL mode for true zero-syscall operation on supported kernels
5. Integrate with tokio via `tokio-uring` or manual eventfd registration

**Option B - Remove io_uring, use sendmmsg:**
1. Remove the io_uring implementation entirely
2. Rely on `sendmmsg()` for batched UDP sends (already partially implemented)
3. `sendmmsg` provides real batching with a simpler programming model
4. Document the decision and rationale

**Recommendation:** Option B unless io_uring performance is specifically needed AND someone commits to a proper async implementation. A broken io_uring is worse than no io_uring - it adds complexity and mutex contention for zero benefit.

## Acceptance Criteria
**If Option A:**
- io_uring submissions are batched (not per-packet)
- Completions are harvested asynchronously
- No thread blocking per packet
- Measurable throughput improvement over sendmmsg in benchmarks
- Proper error handling per-CQE

**If Option B:**
- io_uring code removed cleanly
- sendmmsg path is the canonical Linux fast path
- No performance regression vs current (trivial since current io_uring is synchronous)
- Documentation updated

## Dependencies
- Linux kernel >= 5.6 for io_uring (if Option A)
- `sendmmsg` availability (if Option B, standard on Linux)
- Related: TODO-135 (mutex poisoning in uring.rs)
- Related: TODO-90 (linux send path collapse)

## Affected Files
- `src/transport/uring.rs` (rewrite or remove)
- `src/transport/udpfast.rs` (sendmmsg path, may become primary)
- `src/transport/mod.rs` (module wiring)
- `src/transport/batch.rs` (batch integration)
- `Cargo.toml` (io_uring dependency)
