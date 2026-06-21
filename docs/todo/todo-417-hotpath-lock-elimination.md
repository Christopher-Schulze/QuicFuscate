---
id: TODO-417
title: Hot-Path-Lock-Entfernung (bündelt TODO-396 + TODO-397 + TODO-398)
severity: HIGH
phase: "2"
priority: P1
status: OPEN
created: 2026-07-23
depends_on: [TODO-418]
supersedes: [TODO-396, TODO-397, TODO-398]
---

# TODO-417: Hot-Path-Lock-Entfernung

## Problem

Three independent lock-contention problems on the QUIC data-plane hot path, each small in isolation but collectively a throughput killer under load:

### TODO-397: FEC Mutex (std::sync vs parking_lot)
`AdaptiveFec` uses `std::sync::Mutex` at `src/fec/mod.rs:2991-2994` while the rest of the stack uses `parking_lot::Mutex`. `std::sync::Mutex` has worse contention behavior (spinning, parking overhead) and is inconsistent with the codebase standard.

### TODO-398: CryptoContext RwLock per-packet
`CryptoContext` acquires `RwLock` for every `seal`/`open` operation. 1-RTT keys change rarely (only on key-update), so the lock is unnecessary in steady state. Under high throughput, this adds a read-lock acquisition per packet in both directions.

### TODO-396: Brain apply_policy write-lock storm
`brain::apply_policy` acquires `st.write()` up to **5 times per ACK** processing. Additionally, histogram vectors are reallocated via `.collect()` on each call instead of being reused.

## Acceptance

1. **FEC Mutex** (`src/fec/mod.rs`):
   - `std::sync::Mutex` replaced with `parking_lot::Mutex` (drop-in).
   - All `Arc<Mutex<AdaptiveFec>>` call sites updated.
   - No `std::sync::Mutex` remains in `src/fec/`.
   - `cargo test --lib` green.

2. **CryptoContext RwLock** (`src/crypto/mod.rs` or `src/transport/connection.rs`):
   - 1-RTT keys stored in `ArcSwap<DataAead>` (lock-free reads via `arc_swap::ArcSwap::load()`).
   - `seal`/`open` on 1-RTT path acquires **no lock** in steady state.
   - Key-update writes via `arc_swap::ArcSwap::store()`.
   - Initial/handshake keys retain RwLock (they change during handshake, not on hot path).
   - `arc_swap` added to `Cargo.toml` dependencies.
   - `cargo test --lib` green.

3. **Brain apply_policy** (`src/brain.rs`):
   - `apply_policy` collects all policy deltas in a local `Vec`, acquires `st.write()` **exactly once** at the end, applies all deltas.
   - Histogram vectors pre-allocated (struct fields or `thread_local!`), not `.collect()`ed per call.
   - `cargo test --lib` green.

4. **Profiling validation** (from TODO-418):
   - Flamegraph after changes shows reduced lock-contention samples compared to baseline.
   - Throughput improvement documented in `docs/profiling/lock-elimination-results.md`.
   - No regression in latency or loss handling.

## Fix Plan

### Step 1: FEC Mutex → parking_lot (lowest risk, do first)
1. Add `parking_lot` to `Cargo.toml` if not already present (check — it's likely already a dep for other modules).
2. In `src/fec/mod.rs`, replace `use std::sync::Mutex` with `use parking_lot::Mutex`.
3. Replace `Arc<std::sync::Mutex<AdaptiveFec>>` with `Arc<parking_lot::Mutex<AdaptiveFec>>`.
4. Update all `.lock()` call sites — `parking_lot::Mutex::lock()` returns guard directly (no `.unwrap()` needed, unlike std).
5. Run `cargo test --lib`.

### Step 2: CryptoContext ArcSwap (medium risk, do second)
1. Add `arc_swap` to `Cargo.toml`: `arc_swap = "1"`
2. Identify where 1-RTT `DataAead` is stored — likely in `CryptoContext` or `Connection` struct.
3. Replace `RwLock<DataAead>` with `ArcSwap<DataAead>`.
4. Read path: `let aead = ctx.data_aead.load();` — returns `arc_swap::Guard<Arc<DataAead>>`, derefs to `DataAead`.
5. Write path (key-update): `ctx.data_aead.store(Arc::new(new_aead));`
6. Ensure `DataAead` is `Clone` or wrapped in `Arc` (it's an enum, likely already cheap to clone or Arc-wrapped).
7. Keep `RwLock` for Initial/Handshake keys (not hot path).
8. Run `cargo test --lib` + crypto-specific tests.

### Step 3: Brain lock coalescing (medium risk, do third)
1. In `src/brain.rs`, `apply_policy`:
   - Identify all `st.write()` acquisition points (up to 5 per ACK).
   - Collect all policy deltas into a local `Vec<PolicyDelta>` (or individual local vars).
   - Acquire `st.write()` once.
   - Apply all deltas in the single critical section.
   - Drop guard.
2. Histogram vectors: move from `.collect()` per-call to pre-allocated struct fields or `thread_local!` buffers.
3. Run `cargo test --lib` + brain-specific tests.

### Step 4: Profiling validation
1. Re-run TODO-418 profiling scenarios (a) and (b) after all three changes.
2. Compare flamegraphs: lock-contention samples should be significantly reduced.
3. Document in `docs/profiling/lock-elimination-results.md`.

## Files

- `src/fec/mod.rs` (Mutex → parking_lot)
- `src/crypto/mod.rs` or `src/transport/connection.rs` (RwLock → ArcSwap)
- `src/brain.rs` (lock coalescing + histogram reuse)
- `Cargo.toml` (add `arc_swap` if not present)
- `docs/profiling/lock-elimination-results.md` (new — validation results)

## Risks

- **ArcSwap**: `Guard` lifetime must be carefully managed — the guard keeps the old `Arc` alive, so no use-after-free. Standard `arc_swap` pattern, well-documented.
- **Brain lock coalescing**: Must ensure all 5 write-lock sites are truly independent (no read between writes that depends on prior write). If they're dependent, coalescing changes semantics.
- **parking_lot**: API differs slightly from std (no poisoning, `lock()` returns guard directly). All `.lock().unwrap()` patterns must be changed to `.lock()`.

## Notes

- This task **bundles** TODO-396, 397, 398 because all three are lock-path optimizations, all need the same profiling validation (TODO-418), and all carry correctness risk best reviewed together.
- No UI changes.
- Precondition: TODO-418 (profiling baseline) must be complete to validate "before" state.
- TODO-396, 397, 398 individual files are marked `superseded_by: TODO-417` and should not be implemented separately.
