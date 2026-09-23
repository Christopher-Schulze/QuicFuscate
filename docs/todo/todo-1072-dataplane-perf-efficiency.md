---
id: TODO-1072
title: Dataplane performance and efficiency optimization cluster
severity: MED
phase: M
priority: P1
status: OPEN
created: 2026-09-22
depends_on: [TODO-1071]
---

# TODO-1072: Dataplane performance and efficiency optimization

## Why

Efficiency is the product: throughput per CPU cycle and per wire byte. The
historical TODO-913..TODO-964 series has already landed except TODO-927's
native x86_64 io_uring decision. Replaying that series would duplicate closed
work. TODO-1071 must first establish a trustworthy current baseline; this
cluster then owns only newly measured dataplane bottlenecks.

## Scope

- Inventory the remaining dataplane costs from TODO-1071 and current source;
  exclude archived work and preserve TODO-927 as the io_uring decision owner.
  Rank candidates by measured cost share and plausible net benefit.
- Allocation elimination: per-datagram `Vec`/`String`/`Arc::clone` removals,
  flat staging buffers, pooled packet handles.
- Syscall/batching: `sendmmsg`/GSO/GRO coverage, io_uring paths, drain caps.
- Memory path: pool checkout costs, zeroize policy costs (measured, kept on).
- Congestion/recovery hot loops: sent-map, ACK processing, retransmit queues.
- Every item: before/after cell from the same harness, committed separately.

## Non-goals

- No wire-shape changes — packet form is frozen (TODO-1052 family).
- No crypto-owner changes — ring/libaegis boundaries stay.
- No readability-for-speed trades that hurt auditability.

## Methodology

- Omega release builds + criterion benches + targeted `perf`-style counters
  where available (single-core is fine for relative before/after).
- macOS benches allowed for iteration speed; only Omega numbers close an item.
- Give each independently verifiable new fix its own task detail and commit;
  this cluster owns the ranking and aggregate verdict, not duplicate fixes.

## Acceptance

- [ ] Current TODO-1071 baseline, profiler samples, and source owner map
      produce a ranked list of remaining bottlenecks, with exact measurement
      cells and a named owner for each; closed TODO-913..TODO-964 items are
      listed only as historical baseline changes.
- [ ] Each new fix has a separate linked task with the same-host before/after
      delivered throughput, CPU per delivered packet, p99 latency, wire bytes,
      and loss where applicable; include repeated-run spread and the unchanged
      correctness/security gates.
- [ ] Net dataplane improvement vs the TODO-1071 baseline: reported honestly,
      including items that measured negative and were reverted.

## Risks

- Micro-optimizations regressing on different hardware — mitigate by keeping
  each change reversible and measured on the target host.

## Rollback

Each new optimization has its own task and commit. A negative measurement
keeps the measured baseline and records the rejected change in that task.

## Sub-Tasks

- [ ] Confirm TODO-1071's current measurement gates and reconcile the
      TODO-913..TODO-964 archive against any still-open owner such as TODO-927.
- [ ] Profile the production dataplane on the target host and record a ranked
      candidate table with source path, call site, workload, cost share,
      expected effect, proof gate, and new task ID for every selected fix.
- [ ] Execute the selected linked tasks in measured-value order; update the
      aggregate same-host result only after each independent gate passes.
