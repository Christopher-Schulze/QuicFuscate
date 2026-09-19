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

## Scope
- Client connected-socket inbound path first (no per-packet sockaddr needed).
- Server demux path only if addr metadata stays affordable (UDP_GRO cmsg
  handling must keep working - check cmsg support under multishot).
- Feature-detect at init; keep the current per-slot path as fallback.
- GRO super-buffer splitting must keep working (check `msg_flags` /
  `UDP_GRO` ancillary availability per CQE).

## Acceptance
- Multishot+provided-buffer recv live on the connected path behind the same
  probe/fallback discipline as the existing worker.
- `rt-transport-uring` extended: multishot loopback, buffer-ring refill,
  GRO split, and fallback tests green on Omega and the
  `linux-transport-uring` CI lane.
