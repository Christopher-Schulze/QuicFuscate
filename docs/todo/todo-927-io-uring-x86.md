---
id: TODO-927
title: Verify current io_uring TX performance on native x86_64
severity: MEDIUM
phase: "P"
priority: P2
status: PARTIAL
created: 2026-09-17
depends_on: []
---

# TODO-927: Verify current io_uring TX performance on native x86_64

## Why

`src/optimize/uring_batch.rs` and `uring_batch/worker.rs` own the Linux TX
fast path. TODO-902's duplicate flatten is fixed; `channel(1)` is deliberate
backpressure for one pointer-backed ring owner. `submit_and_poll` uses a
bounded spin/yield/sleep policy rather than the old fixed 1 ms sleep. Omega
proved current behavior on aarch64 Linux, but no native x86_64 measurement
compares this path to the current `sendmmsg` fallback. A different completion
wait is a candidate only if measured idle CPU or tail latency justifies its
shutdown/deadline complexity.

## Resolution (PARTIAL)

Implemented and verified on Omega (aarch64, kernel 6.17):

- **Flat payload submission** (copy 1 of N removed): `WorkerRequest`
  carries one flat `Vec<u8>` plus a span table instead of one `Vec`
  per packet; `UringBatchSender` storage migrated from
  `Vec<Vec<u8>>` to `payload_flat` + `payload_spans` + `packet_addrs`.
  The worker handoff now *adopts* the flat buffer via
  `send_batch_flat_with_wait` / `send_batch_to_flat_with_wait` -
  zero payload copies between caller flattening and iovec publication.
  Borrowed-slice public API (`send_batch`, `send_batch_to`,
  `*_with_disposition`) unchanged; shared `finish_*_with_wait` tails
  keep one chunk-submit implementation for both entry styles.
- **Completion polling**: `submit_and_poll` no longer sleeps a fixed
  1 ms per iteration. It spins briefly (64 `spin_loop` rounds - UDP
  sendmsg CQEs land in microseconds), then escalates through
  `yield_now` + exponential sleep capped at 500 us. Shutdown and
  deadline checks stay responsive at every escalation level.
- **`channel(1)` kept deliberately**: the worker owns exactly one
  sender/ring whose staging is pointer-backed; requests serialize by
  design. A deeper queue only lets a waiting batch exceed the 500 ms
  caller deadline behind a 250 ms operation - spurious quarantines
  with zero throughput gain. Depth 1 = bounded backpressure; extra
  submitters take the per-packet fallback. Documented at the channel
  construction site.
- **`UringRecvBatch` GRO cmsg storage**: every `RecvMsg` slot now arms
  a 32-byte aligned `CmsgSlot`; `drain_completions` parses `UDP_GRO`
  and restores segment boundaries (one `RecvCompletion` per segment).
  `msg_controllen`/`msg_flags` are re-armed before each repost. A
  control-pointer ownership check fails closed if `msg_control` ever
  escapes slot storage.
- **Client GRO + io_uring**: `try_init_uring_recv` probes
  `enable_udp_gro_fd`; on success it uses `with_defaults_gro`
  (contiguous 65,535-byte slots - pool blocks are MTU-sized). If the
  GRO receiver cannot be created, `UDP_GRO` is disabled again before
  the pool fallback so no MSG_TRUNC tail loss can occur. The
  `not(feature = "io_uring")` gate on the client's socket-level
  `enable_udp_gro` is removed; both inbound paths are now
  cmsg-correct. New `disable_udp_gro_fd` helper in qf-transport-udp.

Verification (Omega aarch64, `--features io_uring`):

- `cargo check`: 0 warnings.
- `cargo clippy -p quicfuscate -p qf-transport-udp`: clean.
- `cargo test --lib uring`: 18/18, including the new
  `recv_gro_preserves_segment_boundaries` loopback test (one GSO
  `sendmsg` -> segment boundaries restored through the io_uring CQE
  drain; accepts coalesced or uncoalesced kernel behaviour).
- `cargo test -p qf-transport-udp`: 14/14.
- Full library suite (`--features io_uring`): 1754/1754.

## Still open

- **x86_64 native evidence** - unchanged: needs a real x86_64 host.
  aarch64 verification is complete; do not claim x86 results from
  cross-compilation.
- **Event-driven CQE wait**: the backoff cap is 500 us, not a
  `io_uring_enter(IORING_ENTER_GETEVENTS)` block. A blocking-enter
  redesign must preserve the shutdown flag + deadline polling, which
  the current loop guarantees. Measure before implementing; this is not an
  unconditional replacement requirement.

## Native execution plan

- Use one named x86_64 Linux host with kernel version, CPU topology, Rust
  toolchain, feature set, and exact commit recorded. Require a working
  `io_uring` capability probe and show the worker is actually selected;
  a fallback run is not io_uring evidence.
- Compare current io_uring TX and `sendmmsg` on the same host with the same
  packet-size distribution, concurrency, destination pattern, and offered
  load. Collect at least five repeated trials per arm, median and spread for
  delivered packets/s, accepted bytes/s, p50/p99 send completion latency,
  CPU per delivered packet, loss, and fallback/quarantine counters. Freeze
  the workload and pass criteria before examining results.
- If io_uring is slower or less reliable under the declared workload, keep
  `sendmmsg` as the selected path for that workload and record the exact
  policy change or a follow-up fix. Do not force a speculative ring redesign.
- Profile completion waiting separately under idle, low-rate, and saturated
  traffic. Change the wait strategy only if the measured CPU/latency benefit
  exceeds the cost and a bounded shutdown/deadline wake mechanism is proven
  by a real kernel test.

## Acceptance

- ~~No `thread::sleep` on the completion path.~~ Done (spin->yield->
  capped-sleep backoff; a fixed millisecond sleep no longer exists).
- ~~Channel depth >= 4.~~ Rejected by analysis - see "Resolution";
  depth 1 is the correct bounded-backpressure choice for a single
  serial sender.
- Native x86_64 measurements produce a truthful route-selection verdict
  against `sendmmsg` under frozen workloads. Any claimed io_uring advantage
  requires no worse delivered throughput or loss and a measured CPU or tail
  latency win with repeated-trial spread; otherwise select the proven
  fallback and record the regression as a separate task.
- ~~Omega aarch64: compiles and runs under `io_uring` feature.~~ Done.
