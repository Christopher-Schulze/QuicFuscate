---
id: TODO-894
title: Cap EnvSnapshot per ACK in Brain send path
severity: HIGH
phase: S
priority: P0
status: DONE
created: 2026-08-21
depends_on: []
---

# TODO-894: Cap EnvSnapshot per ACK in Brain Send Path

## Objective
Remove `EnvSnapshot::capture()` (full `env::vars_os` with millions of allocs) from the per-ACK hot path in `src/brain.rs:606`. Cache one snapshot per `update_state` (every 64 packets or 10ms) instead of per `on_ack` in the send path.

## Verified Evidence
- `src/brain.rs:606` `EnvSnapshot::capture()` inside `on_ack`/`on_packet_recv` hot path - verified via read (drain_pending_histogram, histogram decay loops 238,358,414).
- `crates/qf-common/src/env_utils.rs:18` `capture() -> Self` does `env::vars_os` collection.
- Impact: millions of allocs under steady 10k pps, dominates brain overhead in flamegraph.

## Non-Goals
- No Brain policy change, no threshold tuning.

## Acceptance
- No `EnvSnapshot::capture()` inside `on_ack` or `send` hot loop (grep 0 hits in `brain.rs` hot path).
- `cargo bench --bench ci_regression -- brain` unchanged median.
- `cargo test --features rust-tests` brain tests green.

## Out of Scope
- Histogram/JS changes owned by separate TODO.

## Deviations
None.
