# TODO 89: Hardware-Adaptive AEAD Backend Selection Tightening

## Scope
- `src/simd.rs`
- `src/crypto.rs`
- `src/optimize.rs` hardware detection inputs
- AEAD planner telemetry/tests/docs
- hardware-detection and planner-backed AEAD selection

## Problem Statement
- The product contract is already narrowed correctly to:
  - `Aegis128L`
  - `Morus1280_128`
- Internally, the planner still chooses among retained AEGIS backends (`Aegis128L`, `Aegis128X4`, `Aegis128X8`) based on hardware/workload heuristics.
- That is the right basic shape, but the selection story should be re-audited and tightened so it stays maximally crisp:
  - internal batching backends remain internal
  - hardware detection remains the single truth
  - MORUS remains the clean fallback posture where AES hardware is not appropriate

## Desired End State
- Product policy stays exactly:
  - `Aegis128L`
  - `Morus1280_128`
- Internal planner chooses the best retained backend for the actual machine and workload.
- `Aegis128X4` / `Aegis128X8` stay implementation backends only, not product-facing suites.
- Hardware detection remains centralized and authoritative.

## Current Truth Snapshot
- The current SSOT chain is already structurally right:
  - `FeatureDetector` in `src/optimize.rs`
  - `AccelerationPlanner` / `CryptoPlan` in `src/simd.rs`
  - `CryptoAeadPlan`
  - `build_data_aead(...)` in `src/crypto.rs`
- Product-facing override/config truth is already narrowed:
  - `auto`
  - `aegis-128l`
  - `morus`
- Internal retained backends still exist and are real:
  - `Aegis128L`
  - `Aegis128X4`
  - `Aegis128X8`
  - `Morus`
- Current remaining task is therefore not broad crypto cleanup.
- It is a tighter and more explicit hardware/workload-selection contract for the internal AEGIS backend family.

## Architecture Direction
- Keep one SSOT chain:
  - `FeatureDetector`
  - `AccelerationPlanner`
  - `CryptoAeadPlan`
  - concrete AEAD backend construction in `src/crypto.rs`
- Tighten semantics inside that chain:
  - product contract says "AEGIS-L family or MORUS"
  - planner chooses internal retained AEGIS backend width
  - crypto construction only realizes that already-decided backend

## Selection Rules To Make Explicit

### Product Level
- Public policy remains:
  - `Aegis128L`
  - `Morus1280_128`
- No public widening back to `X4` / `X8`.

### Internal Backend Level
- `Aegis128X4` and `Aegis128X8` are allowed only as internal throughput backends.
- They should be selected only when both are true:
  - hardware genuinely supports the profitable path
  - workload size/shape justifies the wider batching backend

### Fallback Level
- MORUS remains the explicit non-AES / non-hardware-AES posture.
- If AES-backed AEGIS is not the right choice on the actual machine, planner behavior should degrade cleanly and intentionally.

## Non-Negotiables
- Keep `Aegis128L`.
- Keep `Morus1280_128`.
- Keep retained AEGIS acceleration backends where they genuinely win.
- Keep MORUS as the deliberate non-AES fallback posture.
- Do not broaden the public crypto contract again.

## Work Breakdown
- [x] Re-audit `FeatureDetector` capability gating used by AEAD selection.
- [x] Re-audit `AccelerationPlanner::crypto_*` heuristics for current hardware-profile mapping.
- [x] Make backend-width selection rules explicit for:
  - x86 AESNI/AVX/AVX2/AVX512/VAES cases
  - aarch64 AES/NEON/SVE2 cases
  - scalar / non-AES fallback cases
- [x] Tighten length-/profile-based selection rules for retained AEGIS internal backends.
- [x] Revalidate fallback semantics for x86, aarch64, and scalar/non-AES situations.
- [x] Add or tighten tests, telemetry expectations, and docs so backend-selection truth stays stable.

## Detailed Execution Plan

### Phase 1: Capability-Gating Audit
- Reconcile which exact hardware features are required for:
  - any AEGIS family use
  - `Aegis128X4`
  - `Aegis128X8`
  - MORUS fallback preference
- Ensure this remains owned by `FeatureDetector`, not ad hoc local checks.

### Phase 2: Planner Tightening
- Audit `AccelerationPlanner::CryptoPlan` defaults and length-aware paths.
- Make explicit where the planner decides:
  - scalar/non-AES fallback
  - base `Aegis128L`
  - internal `X4`
  - internal `X8`
- Tighten those rules so they are defensible by hardware and workload, not just historical drift.

### Phase 3: Runtime Construction Confirmation
- Keep `build_data_aead(...)` in `src/crypto.rs` as the simple realization layer.
- Confirm that config/override inputs never widen product semantics again.
- Keep compatibility aliases only as aliases folding back into the narrow contract.

### Phase 4: Regression/Truth Hardening
- Extend tests/guardrails so regressions fail if:
  - public posture widens again
  - internal backend selection bypasses hardware truth
  - MORUS fallback stops being the clean non-AES posture
  - docs drift from actual planner behavior

## Acceptance Criteria
- [x] Public AEAD contract remains exactly `Aegis128L` plus `Morus1280_128`.
- [x] `Aegis128X4` / `Aegis128X8` remain internal-only backend concepts.
- [x] Planner/hardware detection produce defensible backend choices on supported targets.
- [x] MORUS remains the clean fallback posture where AES-backed AEGIS is not the right choice.
- [x] Docs/comments/tests reflect the same selection truth.

## Validation Matrix
- Code/behavior checks must prove:
  - product override/config surface still exposes only the narrow contract
  - internal planner can still choose widened AEGIS backends where justified
  - unsupported hardware falls back cleanly
  - docs and guardrails enforce the same truth
- Required validation commands before closure:
  - `cargo check`
  - `cargo test --features rust-tests crypto`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
  - `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Notes
- This is not a request to remove internal AEGIS batching work.
- It is a request to make the internal selection path maximally sharp and honest.
- March 9, 2026 final closure:
  - `CryptoPlan::for_length(len, features)` now actually uses workload length instead of ignoring it
  - internal AEGIS width selection is now explicit and narrow:
    - small payloads -> `Aegis128L`
    - medium payloads -> `Aegis128X4`
    - large payloads on profitable x86 hardware -> `Aegis128X8`
  - ARM AES/NEON now follows the same cleaner split:
    - small payloads -> `Aegis128L`
    - normal transport payloads -> `Aegis128X4`
  - `select_data_aead(...)` now routes auto selection through `CryptoAeadPlan::select_for_len(...)` with `crate::transport::MIN_CLIENT_INITIAL_LEN` as the named transport-default workload
  - focused regression coverage exists for:
    - `x86_small_payload_uses_single_lane_aegis`
    - `x86_mid_payload_uses_x4_when_aes_is_available`
    - `x86_large_payload_uses_x8_only_when_hardware_supports_it`
    - `x86_large_payload_without_vaes_stays_x4`
    - `arm_small_payload_uses_single_lane_aegis`
  - validation is green:
    - `cargo clean`
    - `cargo test --features rust-tests x86_small_payload_uses_single_lane_aegis --lib`
    - `cargo test --features rust-tests x86_large_payload_uses_x8_only_when_hardware_supports_it --lib`
    - `cargo test --features rust-tests x86_large_payload_without_vaes_stays_x4 --lib`
    - `cargo test --features rust-tests arm_small_payload_uses_single_lane_aegis --lib`
    - `cargo check`
    - `cargo clippy --all-targets --all-features -- -W clippy::all`
    - `bash scripts/tests/audits/audit-runtime-guardrails.sh`
