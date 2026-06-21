# Release Task: Property-Based and Fuzz Robustness

## Scope
- Strengthen correctness guarantees for FEC, crypto, and transport invariants beyond fixed test vectors.

## Current State
- Completed on 2026-02-12:
  - Added `proptest` under `[dev-dependencies]` in `Cargo.toml`.
  - Added dedicated property suite: `scripts/tests/rust/rt-property-suite.rs`.
  - Added properties for:
    - varint roundtrip invariants,
    - stream frame encode/decode invariants,
    - ChaCha20-Poly1305 roundtrip invariants,
    - single-loss FEC recovery invariants.
  - Integrated property suite into `scripts/tests/suites/test-security-fuzzing.sh`.

## Plan
1. Add property-based test framework for Rust test targets.
2. Implement generators and properties for:
   - FEC encode/decode invariants across random payloads and windows.
   - Crypto roundtrip and tamper-detection invariants.
   - Transport frame parse/serialize invariants.
3. Keep fuzz targets and add a minimal release smoke profile for bounded runtime.
4. Add nightly extended profile for deeper fuzz/property runs.

## Acceptance Criteria
- Property tests run in stable CI mode with bounded case count.
- Optional deeper run profile is documented for nightly/release candidates.
- Failures emit minimized repro seeds/cases.

## Deliverables
- Property test module(s) in Rust tests.
- Updated `scripts/tests/suites/test-security-fuzzing.sh` to execute the dedicated property suite.
- Documentation update with exact commands.

## Verification
- `cargo test --test rt-property-suite --features rust-tests` -> pass.
