---
id: TODO-1008
title: Evaluate io_uring send bundles / provided-buffer sends for TX batching
severity: LOW
phase: S
priority: P3
status: OPEN
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

## Scope
- First measure whether the current per-SQE `SendMsg(Zc)` batch is actually
  the remaining bottleneck after TODO-902/1005 (perf on Omega: syscall vs
  stack-descent share per datagram).
- If per-request overhead dominates: prototype bundle-send for the
  connected client path; verify kernel support on target floors
  (bundle send landed ~6.10/6.11 era - confirm exact version before
  designing the probe).
- Compare against the simpler alternative already available: wider GSO
  runs (fewer syscalls, same wire output).

## Acceptance
- Either a measured adoption with before/after pps on Omega, or a written
  rejection with the numbers showing why current batching suffices.
