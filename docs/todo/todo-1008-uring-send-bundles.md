---
id: TODO-1008
title: Evaluate io_uring send bundles / provided-buffer sends for TX batching
severity: LOW
phase: S
priority: P3
status: DONE
created: 2026-09-19
depends_on: ["TODO-1007"]
---

# TODO-1008: io_uring send bundles evaluation

## Objective
Upstream io_uring added provided-buffer sends and "bundles"
(`IORING_RECVSEND_BUNDLE`): one request picks N buffers from a send buffer
ring and pushes them through the networking stack in a single traversal
(socket lock, backlog flush, qdisc) instead of N full descents. Axboe's
proxy benchmarks reported ~36% improvement over manual per-send handling,
plus simpler ownership (send ring is FIFO = serialized sends without
backlog tracking).

Our TX path already batches at the SQE level (one submit for N `SendMsg`
SQEs) and just eliminated the double flatten (TODO-902). Bundles would
trade per-SQE `msghdr` setup for buffer-ring entries - but they work on
contiguous byte ranges, while UDP datagrams need per-datagram boundaries
(GSO segmentation may cover part of this: one send of a GSO super-buffer
already emits N wire datagrams).

## Implementation plan

Phase 0 - Measure first (no code change):
- On Omega under the e2e throughput harness: `perf stat` syscall counts
  (`io_uring_enter`, `sendmmsg`) + `perf record` breakdown of the worker
  path. Question: after TODO-902/1005 removed the copies, what share of the
  TX path is still per-SQE `msghdr` prep + per-request stack descent?
- If per-request overhead < ~5% of path cost -> reject bundles, record the
  numbers here, close.

Phase 1 - Kernel floor:
- `IORING_RECVSEND_BUNDLE` landed in the ~6.10/6.11 window; confirm the
  exact version from kernel git/liburing changelog before writing any
  probe. Omega runs 6.17 (fine); the `linux-transport-uring` CI lane's
  ubuntu-latest kernel must be probed (if too old, the lane keeps the
  fallback and the test must tolerate it - same two-contract pattern as
  TODO-1004).

Phase 2 - Prototype (only if Phase 0 justifies):
- Send-side provided-buffer ring on the connected client socket: N
  packet-sized buffers per bundle request, one stack descent per bundle.
- Bundle vs datagram boundaries: bundles push byte ranges; UDP datagram
  boundaries need either GSO super-buffers (already built by our staging)
  or per-buffer datagram semantics - confirm the API contract before
  designing.
- Head-to-head on Omega: current `SendMsg(Zc)` batch vs bundle-send vs
  wider-GSO runs. Adoption gate: >10% pps at iso-CPU or a measurable
  syscall-count reduction per packet.

## Risks
- Buffer-ring ownership interacts with the quarantine model (TODO-1004):
  a short submit with pending bundle SQEs must still quarantine the sender
  rather than risk stale-pointer execution. Same contract must hold.
- Send buffer rings serialize sends (FIFO) - verify that ordering matches
  the fallback-resend semantics of `FlatReply` (unsent tail slicing).

## Ruled out this research round (recorded so it stays ruled out)
- **io_uring ZC-Rx (`iou-zcrx`, kernel >= 6.15)**: DMA straight into
  userspace pages, but requires NIC header/data split + flow steering +
  specific HW Rx queues configured by the operator. Not controllable on
  cloud VMs or generic consumer NICs - adoption would silently no-op
  everywhere we deploy. Revisit only if deployment targets gain smartNICs.
- **SQPOLL busy-poll as default**: already opt-in via
  `QUICFUSCATE_IO_URING_SQPOLL=1`; busy-polling trades latency for energy/
  CPU - correct as opt-in, no default change.

## Acceptance
- Either measured adoption (Omega before/after pps + syscall counts, CI
  lane green) or a written rejection with the Phase 0 numbers showing why
  current batching suffices.

## Verdict (2026-09-21): reject

Phase 0 + kernel floor, no prototype.

Kernel floor on Omega (`6.17.0-1018-oracle`):
`/usr/include/linux/io_uring.h` exposes `IORING_RECVSEND_POLL_FIRST` and
`IORING_RECVSEND_FIXED_BUF` but **not** `IORING_RECVSEND_BUNDLE`. There
is no liburing on the host. A bundle probe cannot compile against the
shipped uAPI. The `linux-transport-uring` CI lane would need the same
flag and would have to carry a third fallback contract on top of
TODO-1004 quarantine.

Phase 0 cost share (already measured, no new `perf` run needed):
- TODO-1005 removed the per-packet TX memcpy. TODO-1012 replaced the
  non-GSO tail with one `sendmmsg` (Omega: `sendmsg` -31%, socket-TX
  syscalls -15%).
- GSO already does the "one stack descent, N wire datagrams" job
  bundles advertise, using a contiguous super-buffer we already stage.
- The standalone TUN client does not use io_uring (TODO-1020 STAY).
  Bundles would only touch the io_driver / server worker, which is not
  the 1-core TUN ceiling.

Adoption gate (>10% pps at iso-CPU) is unreachable on this host: the
uAPI is missing, and the remaining TX cost after GSO+sendmmsg is not
per-SQE `msghdr` prep. Revisit only if a deployment kernel ships
`IORING_RECVSEND_BUNDLE` in its installed headers **and** a multi-core
io_driver profile shows per-SQE descent above ~5% of path cost.
