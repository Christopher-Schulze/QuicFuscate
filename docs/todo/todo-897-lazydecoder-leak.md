---
id: TODO-897
title: Fix LazyDecoder seen_seqs leak and fastpath death
severity: HIGH
phase: S
priority: P1
status: QUEUED
created: 2026-08-21
depends_on: []
---

# TODO-897: Fix LazyDecoder seen_seqs Leak and Fastpath Death

## Objective
Fix `crates/qf-fec/src/lazy.rs:136-141` `has_gaps()` staying true forever after first permanent loss, which makes `seen_seqs.clear()` at 196 unreachable, leaks HashSet (~0.5-1MB/s at 10k pps), and forces expensive eliminate path for every repair.

## Verified Evidence
- `lazy.rs:136-141` `has_gaps()` checks `last-min+1 > len` - after one permanent gap, forever true.
- `lazy.rs:196-200` `if seen_seqs.len() >= k && is_multiple { clear }` only in `!has_gaps()` branch, unreachable after loss.
- `lazy.rs:174-204` pending logic.

## Acceptance
- `seen_seqs` bounded (e.g., clear on `k` aligned regardless of gaps, or sliding window).
- No unbounded growth under 10k pps with 1% permanent loss (measure via bench).
- `cargo test -p qf-fec --features rust-tests` lazy tests green.

## Out of Scope
- No FEC wire format change.

## Deviations
None.
