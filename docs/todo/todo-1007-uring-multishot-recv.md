---
id: TODO-1007
title: io_uring multishot recv + provided buffer ring for the inbound fast path
severity: MEDIUM
phase: M
priority: P2
status: DONE
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

MEASURED (step 3, 2026-09, Omega kernel 6.17, loopback flood bench
`recv_flood_bench_batch_vs_multishot`, `QF_URING_BENCH=1`, 20k x 1200B
datagrams, pre-buffered then drained; drain-side CPU isolated via
RUSAGE_THREAD so the flood thread's sendmsg cost stays out):
- Phase 1, individual datagrams (WAN-realistic: Internet senders do not
  emit UDP_SEGMENT trains, and receive-side UDP_GRO only coalesces when
  skb->gso_size survives the path - i.e. same-kernel veth/loopback/virtio):
  batch+GRO 313 drain rounds, 1.69 us/dgram CPU; multishot 79 drain
  rounds (4x fewer), 1.19 us/dgram CPU (~30% less).
- Phase 2, UDP_SEGMENT GSO trains (where UDP_GRO genuinely coalesces):
  batch+GRO 20 drain rounds, 0.54 us/dgram; multishot 79 rounds, 1.28
  us/dgram (2.4x more CPU) - each train segment still consumes one
  provided buffer + one CQE.
- The bench also exposed and now covers a production bug fixed in the same
  change: the io_uring instance was built with `IoUring::new(64)` so the CQ
  held only 128 entries. Once full, the kernel parked further completions -
  including the terminating -ENOBUFS CQE - in the overflow list, which only
  surfaces on `io_uring_enter`. The request looked armed while silently dead.
  Fix: `setup_cqsize(entries + 64)` plus one overflow-flushing `submit()` per
  drain while armed.

DECISION (2026-09-20) - multishot is the default client RX path:
- The edge client talks to servers across real networks, where inbound
  datagrams arrive individually (phase 1 profile) - multishot wins both
  metrics there. Phase 2 only materializes on same-kernel deployments
  (VM-to-VM virtio, containers, same-host), which opt out via
  `QUICFUSCATE_IO_URING_RECV_MULTISHOT=0` to get batch+GRO back.
- Per-datagram `conn.recv` cost is identical in both modes (every wire
  datagram enters conn.recv once), so the e2e question collapses to the
  measured delivery-path cost - answered above.
- Bonus: the provided-buffer ring is 64x2KB pool-backed blocks (~128KB)
  versus 64x64KB contiguous GRO slots (~4MB).
- Kernel <5.19 or any register/submit failure falls back to the batch
  path unchanged; -ENOBUFS terminations self-heal via re-arm (78 events
  over the 20k flood, all recovered).

OPEN (step 4):
- Server demux remains on `UringRecvBatch` (needs per-packet sockaddr).
