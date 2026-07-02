# Optimize Refactor and MORUS-1280-128 - Forensic Plan

## Scope
- Refactor `src/accelerate.rs` into the target module structure under `src/optimize/`.
- Preserve 100 percent of public API and behavior.
- Implement MORUS-1280-128 (scalar + SSE2) with telemetry and deterministic dispatch.
- Ensure 32-bit target safety (overflow guards, conversions, bounds).

## Target Module Structure
```
src/optimize/
  mod.rs              # re-exports + FeatureDetector/CpuProfile entrypoints
  unsafe.rs           # existing
  x86_sse2.rs         # existing
  udp.rs              # UDP GSO/GRO, sendmmsg, zerocopy helpers
  random.rs           # RNG, AES-CTR DRBG, shuffle
  iter.rs             # SIMD reductions (sum_f32/sum_u32/sum_u64)
  sort.rs             # SIMD sorting
  string.rs           # String ops, base64, parsing
  compress.rs         # Compression preprocessing
  brain.rs            # Statistics, ML, matrix ops, softmax
  stealth.rs          # Pattern injection, entropy mixing
  transport.rs        # ACK range, bitmap, ECN, congestion helpers
  memory.rs           # Non-temporal memcpy, transpose, prefetch
  crypto/
    mod.rs
    morus.rs          # MORUS-1280-128 (Scalar + SSE2)
    aegis.rs          # AEGIS planners
    planner.rs        # CryptoPlan dispatch
  telemetry.rs        # telemetry counters
```

## Hard Rules
- No deletions. Every extracted file is archived first.
- No mocks, placeholders, or stubs.
- Every slice must pass forensic diff before proceeding.
- Every slice must pass `cargo clean` + `cargo build --features simd-selfcheck`.
- 32-bit constraints are mandatory (no unchecked usize/varint widening).

## Phase 0 - Baseline Freeze
**Goal**: Create a locked baseline before any refactor.
**Inputs**:
- `src/accelerate.rs`
- `src/simd.rs`
**Outputs**:
- `docs/refactor-baseline.md` with:
  - Full public API list (pub fn/struct/enum) with line numbers.
  - Telemetry counter names (explicit list).
  - Dependency graph (use statements).
  - Invariants and forbidden changes.
**Acceptance**:
- Baseline file exists and is complete.
- Telemetry counter list is explicit.

## Phase 1 - Archive Workflow
**Goal**: Guarantee rollback safety.
**Process**:
1. Copy original file to `archive/` before any edits.
2. Naming: `archive/src-accelerate-YYYY-MM-DD-sliceX.rs`.
3. Never overwrite archive files.
**Acceptance**:
- Each slice has a corresponding archive file.

## Phase 2 - Slice Extraction (Forensic)
**Goal**: Extract module code to the target structure without losing logic.
**Slice Order**:
1. telemetry.rs
2. memory.rs
3. transport.rs
4. udp.rs
5. iter.rs
6. sort.rs
7. string.rs
8. random.rs
9. compress.rs
10. brain.rs
11. stealth.rs
12. crypto/ structure only (no MORUS logic yet)
13. mod.rs re-exports

**Per-Slice Workflow**:
1. Archive source file.
2. Extract module content into new file (no wrapper).
3. Replace module block with `#[path = "optimize/<module>.rs"] pub mod <module>;`.
4. Run line-by-line diff (normalized):
   - Remove module wrapper lines (`pub mod X {` and trailing `}`).
   - Normalize indentation to 0.
   - `diff -u` between extracted block and new file must be empty.
5. Verify public API:
   - Count of `pub fn/struct/enum/type` matches baseline for the slice.
6. Build checks:
   - `cargo clean`
   - `cargo build --features simd-selfcheck`
7. Update `docs/todo.md` and owning project docs.

**Acceptance**:
- Diff is zero.
- Build is green.
- Slice is marked done in `docs/todo.md`.

## Phase 3 - MORUS-1280-128 (Scalar + SSE2)
**Requirements**:
- Scalar implementation, fully in Rust.
- SSE2 backend: `#[target_feature(enable = "sse2")]` with 128-bit lanes.
- Dispatch via `FeatureDetector` or crypto planner.
- Telemetry counters:
  - `MORUS1280_SCALAR_OPS`
  - `MORUS1280_SSE2_OPS`
**Tests**:
- Known Answer Tests based on MORUS spec vectors.
- Parity test: scalar vs SSE2 on x86_64.
**Acceptance**:
- Tests pass.
- Telemetry counters increment per backend.
- No AES-NI dependency required for MORUS.

## Phase 4 - Integrity Pass
**Goal**: Forensic verification over all slices.
**Actions**:
- Line-by-line diff for each slice against its archived source.
- Re-run `cargo clean` + `cargo build --features simd-selfcheck` per slice.
- Final `cargo test --features simd-selfcheck` on host.
**Acceptance**:
- All slices verified with zero diffs.
- Builds and tests green.
- `docs/todo.md`, `docs/DOCUMENTATION.md`, and `docs/MAP.md` updated.

## 32-bit Target Requirements
**Targets**:
- `i686-unknown-linux-gnu`
- `armv7-unknown-linux-gnueabihf`
- Optional: `i686-pc-windows-msvc`
**Rules**:
- All conversions from u64 to usize must use checked conversions.
- All varint-derived lengths must be bounds-checked before allocation.
- All SIMD code must be gated by correct target_arch guards.
**Acceptance**:
- `cargo check` for each target (cross or CI when available).
- No integer overflow or usize truncation in optimized paths.

## Rollback Policy
- If any slice diff fails, stop immediately and restore from archive.
- If build fails, revert only the current slice.
- Record any deviation in the relevant TODO detail file.
