# TODO-151: Define and Test Minimum Supported Rust Version (MSRV)

## Status
**COMPLETED**

## Severity
**MEDIUM**

## Context
The project specifies `edition = "2021"` in `Cargo.toml` but does not define a `rust-version` field. This means there is no documented or enforced minimum Rust version. Users and CI do not know which Rust version is the oldest supported, and accidental use of newer Rust features could silently break compatibility.

- `Cargo.toml`: has `edition = "2021"` but no `rust-version` field
- `.github/workflows/ci.yml`: CI matrix does not include MSRV testing

## Root Cause
The `rust-version` field (stabilized in Rust 1.56) was never added to `Cargo.toml`. CI only tests against the latest stable toolchain without verifying backward compatibility.

## Fix Plan
1. Determine the actual MSRV by checking:
   - Feature usage in the codebase (e.g., `LazyLock` requires 1.80, `let-else` requires 1.65)
   - Dependency MSRV requirements (check each dependency's `rust-version`)
   - Run `cargo msrv find` (from `cargo-msrv` tool) to auto-detect
2. Add `rust-version = "X.Y"` to `[package]` section in `Cargo.toml`
3. Add MSRV to CI matrix:
   ```yaml
   strategy:
     matrix:
       rust: [stable, "1.XX"]  # where 1.XX is the MSRV
   ```
4. Test the MSRV build: `rustup install 1.XX && cargo +1.XX build`
5. Document MSRV in documentation.md

## Acceptance Criteria
- `rust-version` field present in `Cargo.toml` with the correct MSRV
- CI matrix includes an MSRV build job
- Project compiles successfully with the declared MSRV
- MSRV documented in docs/documentation.md
- `cargo clippy -- -D warnings` clean on MSRV

## Dependencies
- Knowledge of all Rust feature gates used in the codebase
- All dependency MSRVs must be compatible

## Affected Files
- `Cargo.toml` (add `rust-version` field)
- `.github/workflows/ci.yml` (add MSRV to CI matrix)
- `docs/documentation.md` (document MSRV)
