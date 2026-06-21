# TODO-177: Profile-Guided Optimization for Release Builds

## Status
COMPLETED

## Severity
MEDIUM

## Context
Release builds currently use standard `cargo build --release` without profile-guided optimization (PGO). PGO can yield 10-15% performance improvement by using runtime profiling data to guide compiler optimizations (branch prediction, inlining decisions, code layout). For a performance-critical networking tool like QuicFuscate, this is a significant gain left on the table.

- No PGO instrumented build target exists
- No benchmark workload defined for profile collection
- No script or CI step for PGO pipeline

## Root Cause
PGO requires a multi-step build process (instrumented build -> profile collection -> optimized rebuild) that was never set up. Standard release profile was sufficient for development but leaves measurable performance on the table for production deployments.

## Fix Plan
1. Create `scripts/build/build-pgo-release.sh` implementing the full PGO pipeline:
   - Step 1: Build with `-Cprofile-generate=/tmp/pgo-data` (instrumented build)
   - Step 2: Run representative benchmarks (crypto, transport, FEC) to collect profiles
   - Step 3: Merge profiles with `llvm-profdata merge`
   - Step 4: Rebuild with `-Cprofile-use=/tmp/pgo-data/merged.profdata` (optimized build)
2. Define representative workload for profile collection (use existing benchmarks from `scripts/benchmarks/`)
3. Add optional CI job for PGO release builds (nightly or on-demand)
4. Document PGO build process and expected performance gains

## Acceptance Criteria
- PGO build pipeline available via `scripts/build/build-pgo-release.sh`
- Script handles all steps (instrument, profile, merge, optimize) automatically
- Pipeline documented in docs/documentation.md
- Before/after benchmark comparison demonstrates measurable improvement

## Dependencies
- LLVM toolchain with `llvm-profdata` available
- Existing benchmark suite for profile collection

## Affected Files
- `scripts/build/build-pgo-release.sh` (new)
- `docs/documentation.md`
- `.github/workflows/ci.yml` (optional PGO job)
