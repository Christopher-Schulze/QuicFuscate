---
id: TODO-1007
title: io_uring multishot recv + provided buffer ring for the inbound fast path
severity: MEDIUM
phase: M
priority: P2
status: OPEN
created: 2026-09-19
depends_on: []
---

# TODO-1007: io_uring multishot receive with provided buffers

## Objective
`UringRecvBatch` (`src/optimize/uring_batch/recv.rs`) re-arms one `RecvMsg`
SQE per slot after every completion (`repost_pending` bookkeeping +
per-slot `msghdr`/iovec/cmsg state). That is one SQE submission per packet
generation, plus the re-arm tracking machinery.

io_uring supports `IORING_OP_RECV` with `IORING_RECV_MULTISHOT` plus a
provided-buffer ring: one SQE produces repeated CQEs, each picking a buffer
from the ring - the per-packet re-arm disappears entirely, and buffer
recycling becomes a ring refill instead of slot bookkeeping. Kernel >= 5.19
for multishot recv; the codebase already targets 6.x-era features.

Note (researched 2025): multishot `recvmsg` is less efficient than multishot
`recv` because per-completion `msghdr` ancillary data is copied on the fly
(`io_msg_alloc_async`). If per-packet source addresses are needed (server
demux), evaluate `recvmsg` multishot vs the current per-slot scheme
empirically; for the connected client socket (no per-packet addr), plain
multishot `recv` + provided buffers is the clean win.

## Implementation plan

Current model in `src/optimize/uring_batch/recv.rs`: `slots` arm one
`RecvMsg` SQE each, `repost_pending: Vec<bool>` tracks post-completion
re-arm, per-slot `msghdr`+iovec+GRO-cmsg storage is re-armed before repost
(lines ~600-650). Every received packet costs one SQE slot round-trip.

Step 1 - New `UringRecvMultishot` beside `UringRecvBatch` (same module):
- Init probe: `io_uring_register_buf_ring` with N=16-32 entries sized to the
  pool block stride; one `IORING_OP_RECV` SQE with `IORING_RECV_MULTISHOT`
  and `sqe->flags |= IOSQE_BUFFER_SELECT` (+ `buf_group` id).
- Any `EINVAL`/`EOPNOTSUPP` at register/submit -> keep `UringRecvBatch`
  (same probe/fallback discipline as `enable_uring_worker`).

Step 2 - Completion path:
- `cqe->flags & IORING_CQE_F_BUFFER` -> buffer id =
  `cqe->flags >> IORING_CQE_BUFFER_SHIFT` -> slice ring backing ->
  feed `conn.recv`/`process_inbound_batch` -> push the id back onto the
  ring tail (refill). The `repost_pending`/`armed` machinery and per-packet
  SQE disappears for this path.

Step 3 - GRO decision (the hard constraint):
- Verify whether `UDP_GRO` cmsg data is available per-CQE under multishot
  `recv`. If not available: for the connected client socket compare
  (a) multishot without GRO (per-packet, fewer syscalls, no coalescing) vs
  (b) current per-slot path with GRO (fewer packets to parse). Pick by
  measurement on Omega under the e2e throughput harness; document the
  numbers.
- If GRO per-CQE ancillary IS available (kernel-dependent), multishot+GRO
  is strictly better and the current path retires on that floor.

Step 4 - Server demux: deferred. Per-packet `sockaddr` is required;
upstream notes `recvmsg` multishot copies the `msghdr` on the fly per
completion. Revisit only if measurements show the client win first.

## Risks
- Buffer exhaustion stalls all recv until refill: ring depth must cover the
  worst-case burst (`DRAIN_BATCH_CAP` interplay); add a
  `uring_recv_ring_starved` counter.
- Buffer lifetime: ring backing is owned by us; contents must be consumed
  or copied before refill - same discipline as pool blocks today.
- Kernel < 5.19: probe fails cleanly, fallback unchanged.

## Verification
- `rt-transport-uring` extended: multishot loopback delivery, ring refill
  under burst, exhaustion/starvation counter, GRO parity (or the
  documented no-GRO variant), probe-fallback test.
- Omega: `tun-e2e-netns.sh` + `rt-io-hotpath-kernel-integration` green.
- CI: `linux-transport-uring` lane runs the same suite - no new lane needed.

## Implementation status (2026-09)

DONE (steps 1-2, kernel-verified):
- `UringRecvMultishot` in `src/optimize/uring_batch/recv.rs` beside
  `UringRecvBatch`: mmap'd provided-buffer ring registered via
  `register_buf_ring_with_flags` (bgid 7), one `opcode::RecvMulti` SQE
  (`IORING_OP_RECV|MULTISHOT|BUFFER_SELECT`), bid recovery via
  `cqueue::buffer_select`, ring refill batched into a single tail advance per
  drain. Contiguous and `MemoryPool`-backed modes; pooled completions move
  the filled block into `RecvCompletion` (zero-copy handoff preserved).
  Starvation counter `ring_starved_total` tracks `-ENOBUFS` terminations;
  the request re-arms on any missing `IORING_CQE_F_MORE`.
- Wired into the client engine path: `InboundReceiver` enum in
  `implementations/client/io_driver.rs`; opt-in via
  `QUICFUSCATE_IO_URING_RECV_MULTISHOT=1` with fallback to the existing
  batch path. `UDP_GRO` is deliberately not enabled on the multishot socket
  (no cmsg - a coalesced super-buffer would be un-splittable).
- Kernel-verified on Omega (6.17): `recv_multishot_delivers_and_recycles_buffers`
  (3 waves x 4 datagrams over an 8-entry ring = bid recycling proof) and
  `recv_multishot_zero_length_and_rearm` (zero-len consumes no buffer id on
  6.17 - counted anyway; delivery resumes after) both green; the whole lib
  suite green, clippy clean.

OPEN (steps 3-4):
- A/B measurement vs the GRO batch path on Omega (`tun-e2e-bandwidth-netns.sh`
  or iperf over the tunnel): multishot trades UDP_GRO coalescing for zero
  re-arm; on the connected client socket the bet is re-arm elimination wins
  at high pps, but the number must be measured, not assumed. Default stays
  opt-in until the numbers land.
- Server demux remains on `UringRecvBatch` (needs per-packet sockaddr).
