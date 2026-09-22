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
`## Active` section already lists dozens of verified micro-costs (TODO-913 to
TODO-964: per-datagram allocs, Arc clones, lock re-acquisition, copy paths,
syscall granularity). They were identified but never executed as a series.
This cluster works them in measurement-priority order.

## Scope

- Absorb the open Active micro-items into an ordered work list, ranked by
  measured cost share from TODO-1071 (not by guess).
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
- Each micro-item lands as its own commit with its measurement delta.

## Acceptance

- [ ] Ordered work list committed to this file's Sub-Tasks with measured cost
      share next to each item.
- [ ] Each completed item has a before/after number in its todo.md entry.
- [ ] Net dataplane improvement vs the TODO-1071 baseline: reported honestly,
      including items that measured negative and were reverted.

## Risks

- Micro-optimizations regressing on different hardware — mitigate by keeping
  each change reversible and measured on the target host.

## Rollback

Each optimization is an independent commit; a negative measurement reverts
that commit only, with the reason recorded in the item's entry.

## Sub-Tasks (ordered, to be populated from TODO-1071 data)

- [ ] Ingest Active items TODO-913..TODO-964 into this list with cost rank.
- [ ] Work top-down; close each Active item's entry when its fix lands here.
