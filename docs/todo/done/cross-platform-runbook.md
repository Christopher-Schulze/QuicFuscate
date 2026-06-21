# Cross-Platform Verification Runbook (O3)

## Status
Dropped per user request (2026-01-25). Keep for reference only.

## Purpose
Provide a repeatable, step-by-step execution guide for cross-platform verification.

## Prerequisites
- Access to the target host (see `docs/todo/cross-platform-verification.md`).
- Toolchain installed for the platform.
- Repo cloned at the same commit for all hosts.

## Standard Environment
- `CARGO_TERM_COLOR=always`
- `RUST_BACKTRACE=1`
- Use `--test-threads=1` for stability.

## Per-Host Run Steps
1. `cargo clean`
2. `cargo test --features simd-selfcheck -- --test-threads=1`
3. Test suites:
   - `scripts/tests/suites/test-core.sh`
   - `scripts/tests/suites/test-crypto.sh`
   - `scripts/tests/suites/test-transport.sh`
   - `scripts/tests/suites/test-optimization.sh`
   - `scripts/tests/suites/test-security-fuzzing.sh` (if supported)
4. Benchmark suites:
   - `scripts/benchmarks/suites/bench-crypto.sh`
   - `scripts/benchmarks/suites/bench-fec.sh`
   - `scripts/benchmarks/suites/bench-transport.sh`
   - `scripts/benchmarks/suites/bench-stealth.sh`
5. Archive artifacts under `scripts/out/` and copy summary into `docs/`.

## Host Summary Template
- Host:
- CPU:
- OS:
- Toolchain:
- Suites run:
- Pass/Fail:
- Artifact paths:

## Notes
- AVX-512 runs are blocked without hardware.
- Windows runs may require adjusted paths and shell commands.
