# TODO 92: Crypto/SIMD Layer Hardening and Internalization

## Scope
- `src/crypto.rs`
- `src/simd.rs`
- relevant hardware-detection touchpoints in `src/optimize.rs`
- crypto/SIMD docs and guardrails

## Problem Statement
- The product crypto truth is now much cleaner, but the implementation footprint is still large:
  - product policy
  - hardware detection
  - planner
  - AEAD backend realization
  - SIMD helpers
  - large in-tree backend code
- For outside readers, that still risks looking like too many visible layers at once.

## Desired End State
- A clean three-layer crypto architecture:
  - product contract
  - planner SSOT
  - internal backend/SIMD machine room
- Product posture stays narrow:
  - `Aegis128L`
  - `Morus1280_128`
- Internal AEGIS width backends remain real and retained, but are even more obviously machine-room details.

## Current Truth Snapshot
- Hardware detection is already centralized via `FeatureDetector`.
- Planner choice is already centralized via `CryptoAeadPlan`.
- AEAD realization is already centralized in `build_data_aead(...)`.
- Internal AEGIS backends remain real:
  - `Aegis128L`
  - `Aegis128X4`
  - `Aegis128X8`
- MORUS remains the non-AES fallback.
- The remaining work is not "rewrite crypto".
- The remaining work is sharper layering and further internalization of helper surface.

## Target Architecture

### Layer 1: Product Contract
- only:
  - `Aegis128L`
  - `Morus1280_128`

### Layer 2: Planner SSOT
- one place decides:
  - whether AEGIS or MORUS
  - if AEGIS, which internal width backend
  - based on hardware and workload

### Layer 3: Backend Machine Room
- backend implementations and SIMD helpers stay internal
- planner result is realized, not reinterpreted
- helper surface should not read like a broad public crypto toolbox

## Non-Negotiables
- Keep AEGIS and MORUS.
- Keep `Aegis128X4` / `Aegis128X8` as retained internal backends.
- Keep hardware-aware switching.
- Do not broaden product contract again.

## Work Breakdown
- [x] Re-audit visible crypto/SIMD surface against the three-layer target.
- [x] Internalize remaining non-owner helpers where possible.
- [x] Tighten planner-to-backend realization boundaries.
- [x] Update tests/docs/guardrails to preserve the final layer truth.

## Progress Update
- The first live cut is in:
  - `src/simd.rs`
  - `src/optimize.rs`
  - `src/transport/batch.rs`
- The SIMD acceleration planner is now crate-internal instead of a broad public namespace.
- The planner itself is also smaller:
  - removed dead subplans for FEC, stealth, brain, memory, and utility
  - retained only the data actually used by the active runtime/test consumers:
    - crypto selection truth
    - rust-tests batch sizing truth
- `src/transport/batch.rs` no longer peeks into `plans.transport.has_avx512f` / `has_avx2`.
- It now consumes the narrower planner seam `transport_batch_size()`.
- `src/optimize.rs` bitslice dispatch remains crate-owned:
  - `dispatch_bitslice(...)` is crate-internal
  - `bitslice_policy_tag(...)` is test-only instead of retained lib surface
- This is a real owner gain, not just visibility cosmetics:
  - the planner exposes less broad structure
  - the batch shim consumes less raw planner internals
  - the FEC kernel tag helper no longer survives as normal lib API
- The next live cut is now in `src/crypto.rs`:
  - `Aegis128X4Aead`
  - `Aegis128X8Aead`
  are now internal backend wrappers rather than visible crypto-surface types
  - `Aegis128X4`
  - `Aegis128X8`
  are now crate-internal backend engines rather than broad public crypto types
- This preserves capability and planner truth while tightening the visible contract:
  - `Aegis128L` remains the explicit product-facing AEGIS contract
  - `X4` / `X8` remain retained backend realizations
  - the AEAD auto-path still realizes them internally through `build_data_aead(...)`
- The PQ side is also tighter now:
  - `pq` is crate-internal instead of a broad public crypto namespace
  - `hybrid` stays public because `qftls` really consumes it
  - this keeps the public crypto contract narrower without removing retained PQ capability
- The retained SHA-256 SIMD microbench surface is no longer part of the normal library contract:
  - `Sha256BenchBackend` now exists only behind `feature = "benches"`
  - `simd::bench` now exists only behind `feature = "benches"`
  - `examples/microbench.rs` keeps the normal `profile` and non-SHA benchmark commands buildable without `benches`, but reports a clear feature requirement if the SHA-256 microbench command is requested without that feature
  - `scripts/benchmarks/micro/micro-crypto-all.sh` now opts into `benches` by default so the retained SHA-256 microbench path still works as intended
- Additional dead SIMD side-surface is now removed entirely:
  - dead internal modules removed from `src/simd.rs`:
    - `compress`
    - `pattern`
    - `neural`
    - `sha_ni`
  - the no-longer-owned ARM helper cluster that existed only for those modules was removed with it
  - retained runtime-facing SIMD namespaces are now closer to the real live owner set
- The x86 parity seams are now also more honest:
  - `x86_ack` and `x86_header` are crate-internal instead of broad public namespaces
  - rust parity coverage now uses explicit `rust-tests` hooks at the `simd` root:
    - `canonical_ack_blocks_avx2_for_rust_tests(...)`
    - `canonical_ack_blocks_avx512_for_rust_tests(...)`
    - `validate_header_avx512_for_rust_tests(...)`
    - `validate_header_sse2_for_rust_tests(...)`
  - this keeps runtime ownership intact while removing another pair of raw internal namespaces from the normal library contract
- The last broad crypto helper namespace is now also tighter:
  - `chacha20poly1305` is crate-internal
  - the public contract remains the root re-exported `ChaCha20Poly1305` type
  - runtime code, rust tests, and fuzz targets now depend on the type contract rather than the internal module path
  - this removes one more unnecessary public crypto namespace without weakening functionality

## Detailed Execution Plan

### Phase 1: Surface Inventory
- Classify remaining visible helpers and types in:
  - `src/crypto.rs`
  - `src/simd.rs`
- Separate:
  - product contract
  - planner contract
  - internal backend helpers

### Phase 2: Internalization
- Reduce visibility of helpers that are not real product/planner contract.
- Keep test-only compatibility surfaces only where they have a concrete owner.
- Started:
  - planner namespace internalized
  - dead planner subplans removed
  - bitslice policy tag constrained to tests

### Phase 3: Planner Realization Hardening
- Ensure backend construction only realizes already-decided planner truth.
- Avoid second-guessing hardware/planner decisions lower in the stack.

### Phase 4: Truth Hardening
- Add or tighten tests/guardrails so the three-layer split does not regress.
- Update docs to describe exactly this architecture.

## Acceptance Criteria
- [x] Product contract remains narrow and explicit.
- [x] Planner remains the single backend-selection truth.
- [x] Backend/SIMD machine room is more clearly internal.
- [x] Docs and guardrails preserve the same layer split.

## Validation Matrix
- `cargo check`
- focused crypto/simd rust-tests for planner/backends
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Notes
- The goal is not less capability.
- The goal is less visible sprawl and a harder planner/backend boundary.
