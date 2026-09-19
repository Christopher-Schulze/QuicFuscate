---
id: TODO-902
title: io_uring TX triple-copy and channel1 fix
severity: MEDIUM
phase: S
priority: P1
status: IN_PROGRESS
created: 2026-08-21
depends_on: []
---

# TODO-902: io_uring TX Triple-Copy and Channel1 Fix

## Objective
Fix `src/optimize/uring_batch.rs:543-546,904-927` triple-copy (pool->temp Vec->iovec copy) + `channel(1)` (1 request in flight) + `Sleep(1ms)` polling in io_uring TX path. Use ownership transfer and `submit_and_wait` with channel depth >=8.

## Verified Evidence
- `uring_batch.rs:543-546` copies payload via temp Vec before iovec.
- `worker.rs:41` channel depth 1 limits to 1 request in flight.
- Polling via `Sleep(1ms)` instead of `AsyncFd` on CQ.

## Acceptance
- Zero-copy: pool block directly as iovec, no temp Vec.
- Channel depth 8, `submit_and_wait` event-driven.
- `cargo bench --bench ci_regression -- uring` shows 2x throughput.

## Out of Scope
- No io_uring RX change (already zero-copy at recv.rs:411-437).

## Deviations
- **BLOCKED on Linux environment (2026-08-21):** the io_uring path compiles only behind the `io_uring` feature on Linux; this macOS arm64 host cannot build, run, or verify any change to `uring_batch.rs`/`worker.rs`. The evidence lines are verified real (slot `extend_from_slice` copy at uring_batch.rs:543-546, `channel(1)` at worker.rs:41), but implementing without compile+bench verification would ship unverified claims. Requires a Linux x86_64 host with the QUIC server workload for the 2x-throughput acceptance (Omega is aarch64 and runs no live server loop).
- **Omega unblocked (2026-08-23):** Omega (aarch64 Linux, Rust 1.97.1 + nightly + Miri) is now SSH-accessible with sudo. `ip netns`, `nft`, and `tcpdump` are all available. The io_uring feature compiles on aarch64 and `cargo test --all-features --lib` passes 1793/1793. However, the 2x-throughput acceptance benchmark still requires a real x86_64 server workload with sufficient traffic to prove the improvement; Omega's single aarch64 core is insufficient for pps scaling claims. The remaining blocker is x86_64 benchmark evidence, not Linux access.
- **Stale claims corrected (2026-09-19):** the original "Sleep(1ms) polling" evidence is obsolete - the worker uses `blocking_recv` and the sender already submits through `submit_and_wait`. `channel(1)` is deliberate serialization/backpressure for the single ring owner (documented at worker.rs:47-52); a deeper queue would only let requests expire behind the 250ms operation deadline. The remaining real defect was the double flatten: the caller staged packets into `staging_flat`/`staging_spans` and `send_batch_to_with_disposition` re-flattened them into the request (one ~64-packet memcpy plus two allocations per flush).
- **Implemented (2026-09-19):** `WorkerRequest::ToFlat` + `send_batch_to_flat_with_disposition` adopt the caller's owned buffers in place and return them intact in `FlatToReply`, so the unsent tail can still be resent through the per-packet/GSO fallback. `submit_request` is now generic over the reply payload with a `recover` callback that hands the request's buffers back when the request never reaches the worker (unavailable, queue full, channel closed). Pre-adoption rejections (`ensure_usable`, empty, zc-controlled, admission) are evaluated in the worker arm so the buffers stay returnable; a post-adoption failure clones the retained slots out of the possibly poisoned sender so fallback resend semantics match the old borrowed-packet path exactly.
- **Verified on Omega (aarch64, kernel 6.17):** `cargo check/clippy --features io_uring` clean; `uring_batch_worker_flat_adoption_returns_buffers_intact` proves adoption, intact buffer return, and loopback delivery; full `rt-transport-uring` suite 20/21 (the `uring_sendmsg_partial_send_retry_subsets_deliver_exactly_once` failure reproduces identically on unmodified code - pre-existing injected-failure accounting issue on kernel 6.17, tracked separately); `tun-e2e-netns.sh` PASS with `server io_uring batch worker initialised` in the live server log (real MASQUE traffic over the new path, 0% loss, clean teardown).
- **Client io_driver follow-up (2026-09-19):** the client TUN->QUIC burst loop (`io_driver/runtime.rs`) had the same double flatten - it staged packets into the persistent `batch_flat` slab + `batch_spans`, built a per-flush `SmallVec<[&[u8]; 256]>` of borrows, and `send_batch_with_disposition` re-flattened them into fresh sender buffers. `WorkerRequest::ConnectedFlat` + `send_batch_flat_with_disposition` adopt the slab by value and return it intact in `FlatReply` for sendmmsg fallback and next-iteration reuse. Because `batch_flat` is a ~1 MiB slab whose `len()` exceeds the used extent, adoption now validates `flat_spans_extent` (checked end-of-span arithmetic against `flat.len()`) before admission; the same extent check now guards the unconnected `ToFlat` path, closing a pre-existing unchecked `as_ptr().add(start)` iovec indexing hazard for caller-supplied spans.
- **Still open:** the 2x-throughput acceptance still needs x86_64 benchmark evidence (`cargo bench --bench ci_regression -- uring`); the aarch64 single-core Omega box cannot produce meaningful pps-scaling numbers. True zero-copy (pool block directly as iovec) is intentionally not implemented: SQE iovecs must reference sender-owned storage until CQEs complete, so the single caller-side flatten is the safe minimum for the worker contract.
