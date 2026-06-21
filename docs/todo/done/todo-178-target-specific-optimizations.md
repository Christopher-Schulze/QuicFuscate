# TODO-178: Target-Specific Release Profiles

## Status
COMPLETED

## Severity
LOW

## Context
Release builds use a single generic profile without target-specific CPU optimization flags. Modern x86_64-v3 CPUs (Haswell+) and aarch64 servers benefit from architecture-specific instruction selection, but the current build produces generic binaries that miss these optimizations.

- `Cargo.toml`: single `[profile.release]` with no target-cpu configuration
- No x86_64-v3 profile for modern desktop/server CPUs (AVX2, BMI2, FMA)
- No aarch64 profile for ARM servers (Graviton, Ampere)
- SIMD code in `src/simd/` could benefit from guaranteed instruction availability

## Root Cause
Only a single release profile was configured. Cargo supports custom profiles but no target-specific variants were added for different CPU architectures.

## Fix Plan
1. Add custom Cargo profiles in Cargo.toml:
   - `[profile.release-x86-64-v3]` inheriting from release with `RUSTFLAGS="-C target-cpu=x86-64-v3"`
   - `[profile.release-aarch64]` inheriting from release with `RUSTFLAGS="-C target-cpu=native"` for ARM
2. Create build scripts:
   - `scripts/build/build-release-x86-64-v3.sh`
   - `scripts/build/build-release-aarch64.sh`
3. Add CI matrix entries for target-specific builds (at minimum x86_64-v3 and aarch64)
4. Document available build targets and when to use each

## Acceptance Criteria
- Target-specific release builds available via dedicated scripts
- x86_64-v3 build uses AVX2/BMI2/FMA instructions
- aarch64 build uses NEON/SVE where available
- Documentation lists all build targets with hardware requirements

## Dependencies
- Cross-compilation toolchain for aarch64 (if building on x86)

## Affected Files
- `Cargo.toml` (new profiles)
- `scripts/build/build-release-x86-64-v3.sh` (new)
- `scripts/build/build-release-aarch64.sh` (new)
- `.github/workflows/ci.yml`
- `docs/documentation.md`
