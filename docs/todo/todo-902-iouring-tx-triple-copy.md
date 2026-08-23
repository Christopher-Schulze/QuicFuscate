---
id: TODO-902
title: io_uring TX triple-copy and channel1 fix
severity: MEDIUM
phase: S
priority: P1
status: BLOCKED
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
