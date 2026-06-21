# TODO 57: Secure RNG Truth Alignment

## Scope
- Security-sensitive and performance-oriented randomness surfaces across:
  - `src/rng.rs`
  - `src/optimize/random.rs`
  - RNG call sites in transport/server/admin paths

## Problem Statement (Audit Evidence, 2026-03-05)
- `optimize::random::random_bytes_secure()` is named as a secure entropy API but can route through a custom AES-CTR DRBG path on AArch64.
  - Evidence: `src/optimize/random.rs:50`-`:55`, `:93`-`:96`, `:220`-`:227`
- The repo already has `src/rng.rs` as the canonical security RNG surface, so `optimize::random` creates a second, weaker security story.
- Platform-specific behavior differs under the same API name.

## Objectives
- Ensure security-critical RNG has one canonical truth.
- Align names, docs, and guarantees with actual behavior.
- Keep high-throughput non-security RNG helpers explicit and separate.

## Work Breakdown
### A. Policy Decision
- [x] Decide whether `optimize::random` is non-security-only or must be upgraded to a formal DRBG contract.
- [x] Document platform-specific RNG guarantees explicitly.

### B. API Truthfulness
- [x] Rename or refactor misleading `secure` APIs whose behavior is not canonical `src/rng.rs` security policy.
- [x] Ensure call sites cannot accidentally choose noncanonical RNG for security-sensitive work.

### C. Separation of Concerns
- [x] Keep performance RNG helpers clearly separate from canonical entropy APIs.
- [x] Add guardrails for cross-import mistakes between `src/rng.rs` and `src/optimize/random.rs`.

### D. Validation
- [x] Add tests for platform-specific RNG contract behavior.
- [x] Add audit checks that flag future misleading secure-entropy naming or routing.

## Acceptance Criteria
- [x] Security RNG policy is singular and explicit.
- [x] No API claims stronger security guarantees than it actually provides.
- [x] Platform differences are documented and tested.

## Deliverables
- [x] Clarified RNG contract.
- [x] Refined RNG naming/routing.
- [x] Guardrails for secure-vs-nonsecure RNG drift.

## Progress Notes
- 2026-03-05: Created from deep review of RNG semantics after RNG hardening work exposed remaining contract mismatch in `optimize::random`.
- 2026-03-08: Chose the strict policy direction for this fork: `src/rng.rs` remains the only canonical security entropy surface, and `optimize::random` stays explicitly non-security/test-oriented.
- 2026-03-08: Removed the misleading optimize-side alias `random_bytes_secure(...)` from `src/optimize/random.rs`.
- 2026-03-08: Internal optimize-side DRBG seeding now calls `crate::rng::fill_secure_or_abort(...)` directly with explicit contexts instead of routing through an optimize-side secure-named wrapper.
- 2026-03-08: Updated Rust tests to the clarified split:
  - `rt-random-aes-ctr.rs` now verifies AES-CTR-backed optimize helpers via `random_array_u32(...)` and `random_u64()`
  - `rt-security-suite.rs` now uses `quicfuscate::rng::fill_secure_or_abort(...)` for the actual security entropy check
- 2026-03-08: Extended `scripts/tests/audits/audit-runtime-guardrails.sh` so misleading optimize-side secure RNG aliases are flagged if they reappear.
- 2026-03-08: Validation after the secure-alias removal remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
  - `scripts/tests/audits/audit-runtime-guardrails.sh`
    - Critical: 0
    - Warnings: 0
- 2026-03-08: Tightened the public contract wording in `docs/DOCUMENTATION.md` so `accelerate::random` is described only as non-security/test-only helper surface, even when backed by hardware-assisted helper paths.
- 2026-03-08: Extended the runtime guardrail audit with a second RNG truth check so docs cannot silently drift back into describing `accelerate::random` as a secure or canonical entropy API.
