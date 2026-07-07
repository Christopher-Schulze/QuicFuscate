---
id: TODO-517
title: HintChannel<T> abstraction for brain.rs hint atomics
severity: LOW
phase: S
priority: P1
status: DONE
created: 2026-07-07
depends_on: []
---

# TODO-517 — HintChannel<T> Abstraction for brain.rs Hint Atomics

## Context

`docs/DOCUMENTATION.md` (Future Direction, "Global Atomic State Audit") identifies the
brain.rs hint channel atomics as the **highest-return coupling-reduction target** without
performance impact. Today they are raw `pub(crate) static Atomic*` globals with an
implicit writer/reader contract that requires grep to trace. A reviewer reading
`FEC_INTERVAL_HINT_PKTS.load(Ordering::Relaxed)` in `src/fec/mod.rs` cannot see who
writes it, what units it carries, or what the "0" sentinel means without a codebase hunt.

The audit text erroneously says "Hint channels (4 in brain.rs)" — the code truth is **3**
(`FEC_INTERVAL_HINT_PKTS`, `FEC_REDUNDANCY_PPM`, `INTELLIGENT_STEALTH_LEVEL_HINT`). The
audit table at the same doc correctly says 3. This TODO also reconciles that inconsistency.

## Desired Outcome

A `HintChannel<A: HintAtomic>` newtype wrapping the atomic with an explicit,
self-describing contract (name + writer/reader semantics string), preserving lock-free
`Relaxed` performance (zero-cost after inlining). All call sites use `.load()`/`.store()`
so the raw `Ordering::Relaxed` is encapsulated inside the primitive. The cross-subsystem
data flow becomes greppable and self-describing at the declaration site.

## Design

```rust
pub(crate) struct HintChannel<A: HintAtomic> {
    atomic: A,
    name: &'static str,
    contract: &'static str,
}

pub(crate) trait HintAtomic: Send + Sync {
    type Value: Copy + Default;
    fn load_relaxed(&self) -> Self::Value;
    fn store_relaxed(&self, v: Self::Value);
}

// impl HintAtomic for AtomicU64, AtomicU32 — #[inline] load_relaxed/store_relaxed
// HintChannel::new is const fn (struct construction only, no trait calls)
// HintChannel::load/store are #[inline(always)] delegating to the trait
```

Zero-cost: after inlining the `#[inline]` trait methods, `channel.load()` compiles to the
same single `mov` instruction as the raw `atomic.load(Ordering::Relaxed)`.

## Writer/Reader Contract (captured at declaration site)

| Channel | Type | Writers | Readers | Sentinel |
|---------|------|---------|---------|----------|
| `FEC_INTERVAL_HINT_PKTS` | u64 | `StealthBrain::new` (default 8), `StealthBrain::emit_probe_if_due` (varies ±1), `StealthBrain::apply_policy` actuators | `FecTransportObserver::compute_interval` blending in `fec/mod.rs`, `emit_probe_if_due` read-back | 0 = no hint |
| `FEC_REDUNDANCY_PPM` | u32 | `StealthBrain::new` (default 100_000), `StealthBrain::apply_policy` actuators | `FecTransportObserver::sync_runtime_hints` in `fec/mod.rs` | 0 = no hint |
| `INTELLIGENT_STEALTH_LEVEL_HINT` | u32 | `StealthBrain::apply_policy` (effective_level), `EscalationState::check_escalation` + `check_de_escalation` in `stealth/mod.rs` | `intelligent_stealth_level_hint()` accessor → `StealthManager::intelligent_runtime_level` + `sync_intelligent_level` | 0 = performance baseline |

## Completion Criteria

1. `HintChannel<A>` + `HintAtomic` trait defined in `src/brain.rs`.
2. 3 statics converted; all writers/readers use `.load()`/`.store()` (no raw
   `Ordering::Relaxed` at hint call sites).
3. `intelligent_stealth_level_hint()` accessor and `clear_runtime_hints_for_test()`
   preserved (test-only reset still works).
4. New unit test for the `HintChannel` primitive (round-trip, zero-default, contract
   accessor strings).
5. `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace --all-targets --features rust-tests` all PASS.
6. Docs flushed: `DOCUMENTATION.md` Future Direction (4→3, mark DONE), `MAP.md`,
   `docs/todo.md` row added + this file.
7. No behavior change — pure refactor; existing FEC/stealth/brain tests are the real
   coverage and must remain green.

## Files Touched

- `src/brain.rs` — define primitive, convert 3 statics, update internal call sites.
- `src/fec/mod.rs` — 2 reader call sites (`FEC_INTERVAL_HINT_PKTS`, `FEC_REDUNDANCY_PPM`).
- `src/fec/tests.rs` — 1 test writer call site (`FEC_REDUNDANCY_PPM`).
- `src/stealth/mod.rs` — 3 writer call sites + 2 accessor call sites
  (`INTELLIGENT_STEALTH_LEVEL_HINT`).
- `docs/DOCUMENTATION.md` — Future Direction correction + DONE marker.
- `docs/MAP.md` — hint channel wiring wording.
- `docs/todo.md` — TODO-517 row.

## Execution Evidence

- **Commit:** (this commit)
- **Tests:** 4 new `brain::hint_channel_tests` (`u64_channel_round_trip_and_zero_default`,
  `u32_channel_round_trip_and_zero_default`, `contract_metadata_is_greppable`,
  `production_hint_channels_expose_contracts`) all PASS.
- **Full suite:** `cargo test --workspace --all-targets --features rust-tests` → 1662 lib
  tests + all integration tests PASS, 0 failures.
- **Lint:** `cargo clippy --workspace --all-targets -- -D warnings` PASS.
- **Format:** `cargo fmt --all -- --check` PASS (also restored pre-existing fmt drift in
  `src/audit/mod.rs` and `src/main.rs` introduced by post-TODO-509 audit/mlock/CI commits).
- **Doc reconciliation:** `docs/DOCUMENTATION.md` Future Direction "Hint channels (4 in
  brain.rs)" → "3 in brain.rs" DONE; audit table wording updated; `docs/MAP.md` hint
  channel wiring annotated with `HintChannel<AtomicU32>` + TODO-517 reference.
- **No behavior change:** pure refactor; the `Relaxed` load/store semantics are preserved
  exactly, only the call-site surface changed from `.load(Ordering::Relaxed)` to `.load()`.
