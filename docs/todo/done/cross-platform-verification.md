# Cross-Platform Verification Plan (O3)

## Status
Dropped per user request (2026-01-25). Keep for reference only.

## Goal
Establish a repeatable verification matrix across x86 (AVX2/AVX-512),
Windows/Linux, and ARM targets, with archived artifacts and a cadence.

## Target Profiles
- **x86_64 Linux**:
  - AVX2 baseline (e.g., Zen2/Zen3).
  - AVX-512F/GFNI (e.g., Sapphire Rapids).
- **x86_64 Windows**:
  - AVX2 baseline.
- **ARM64**:
  - Apple_M (macOS).

## Required Tooling
- `scripts/tests/suites/test-core.sh`
- `scripts/tests/suites/test-crypto.sh`
- `scripts/tests/suites/test-transport.sh`
- `scripts/tests/suites/test-optimization.sh`
- `scripts/tests/suites/test-security-fuzzing.sh` (where supported)
- `scripts/benchmarks/suites/bench-crypto.sh`
- `scripts/benchmarks/suites/bench-fec.sh`
- `scripts/benchmarks/suites/bench-transport.sh`
- `scripts/benchmarks/suites/bench-stealth.sh`

## Execution Steps (per host)
1. `cargo clean`
2. `cargo test --features simd-selfcheck -- --test-threads=1`
3. Run test suites above (capture `scripts/out/*`).
4. Run benchmark suites above (capture `scripts/out/*`).
5. Record durable results in `docs/todo.md`, relevant TODO detail files, and `docs/DOCUMENTATION.md`.

## Artifacts
- Store all suite logs under `scripts/out/`.
- Copy summary (host info + results) into `docs/` with date stamp.

## Cadence
- Quarterly minimum for x86_64 (Linux + Windows).
- Per-release for ARM64 (Apple_M).
- AVX-512 only when hardware is available.

## Blockers
- Hardware availability for AVX-512.
- Windows CI host access.
- Signing/notarization credentials (if required by platform tooling).
