# TODO 49: RNG and Entropy Hardening

## Scope
- Randomness generation used by transport/security-sensitive paths:
  - `src/transport/pn.rs`
  - `src/optimize/random.rs`
  - Runtime call sites for connection IDs, tokens, nonces

## Problem Statement (Audit Evidence, 2026-03-05)
- Transport random fallback uses a weak xorshift-like generator if `getrandom` fails.
  - Evidence: `src/transport/pn.rs:137`-`:151`
- RNG surface is split across multiple modules with different guarantees and fallback semantics.
  - Evidence: `src/transport/pn.rs:134`; `src/optimize/random.rs:22`, `:52`, `:350`
- SIMD/random acceleration code includes non-security-oriented patterns that must be clearly scoped away from cryptographic use.
  - Evidence: `src/optimize/random.rs:398` (`AesCtrDrbg::new(&[0x42; 32])`) and related vectorized helpers

## Objectives
- Define a strict RNG policy by use-case class:
  - cryptographic/security-critical
  - protocol randomization/non-security
  - benchmark/test-only
- Remove weak fallback behavior from security-critical paths.
- Make guarantees explicit in docs and code comments.

## Work Breakdown
### A. Policy and API Consolidation
- [x] Define canonical RNG APIs for each security class (`src/rng.rs`: `fill_secure`, `fill_secure_or_abort`, `secure_hex`). [x] 2026-03-05
- [x] Replace ad-hoc random calls in security-critical paths with canonical API (`transport/pn`, `main` admin handlers, server `admin`, `admin_http` session/file nonce paths). [x] 2026-03-05
- [x] Deprecate legacy/random helper paths that bypass policy (policy split documented; guardrails block optimize/accelerate RNG helpers in security-sensitive modules). [x] 2026-03-05

### B. Security Hardening
- [x] Remove weak fallback in transport-critical random generation. [x] 2026-03-05
- [x] Ensure failure behavior is explicit (error or hard fail) where security requires it. [x] 2026-03-05
- [x] Review token/nonce/SCID generation call sites for policy conformance. [x] 2026-03-05

### C. Separation of Concerns
- [x] Mark non-cryptographic RNG helpers as non-security and keep out of security paths. [x] 2026-03-05
- [x] Ensure benchmark/test random helpers cannot be imported accidentally into security paths (guardrail rejects `optimize::random`/`accelerate::random` usage in security-sensitive modules). [x] 2026-03-05

### D. Regression Coverage
- [x] Add tests for entropy-source failure behavior in security-critical functions (`rng::tests::fill_secure_reports_forced_failure`). [x] 2026-03-05
- [x] Add lint/check preventing non-cryptographic RNG in security-sensitive modules (runtime guardrail RNG policy check). [x] 2026-03-05

## Acceptance Criteria
- [x] Security-critical randomness has no weak fallback behavior. [x] 2026-03-05
- [x] RNG policy is centralized and enforced by tests/checks. [x] 2026-03-05
- [x] Non-security RNG helpers are explicitly isolated. [x] 2026-03-05

## Deliverables
- [x] Consolidated RNG policy and API. [x] 2026-03-05
- [x] Hardened transport/security random paths. [x] 2026-03-05
- [x] Regression tests and guardrails. [x] 2026-03-05

## Progress Notes
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-05: `transport::rand::rand_bytes` now fails closed when secure entropy is unavailable (removed xorshift fallback). SIMD random array helpers no longer use fixed `[0x42; 32]` seed and are now seeded from secure RNG.
- 2026-03-05: Added centralized secure entropy module `src/rng.rs` and migrated security-sensitive token/nonce callsites (`main`, `implementations/server/admin.rs`, `implementations/server/admin_http.rs`) to fail-closed API usage.
- 2026-03-05: Added deterministic entropy-failure regression test hooks in `src/rng.rs` and guardrail automation to reject direct RNG fill patterns in security-sensitive modules.
- 2026-03-05: Consolidated remaining direct OS entropy usage in transport control-plane (`transport/recovery`) onto centralized `rng::fill_secure` with explicit non-security fallback behavior preserved.
- 2026-03-05: Extended guardrails to reject direct imports of `optimize::random`/`accelerate::random` in security-sensitive modules, preventing accidental use of non-security random helpers in auth/token/nonce paths.
- 2026-03-08: Closed as complete after correcting the last remaining docs truth drift that still named direct `OsRng` usage for admin session tokens instead of the centralized `src/rng.rs` fail-closed API.
