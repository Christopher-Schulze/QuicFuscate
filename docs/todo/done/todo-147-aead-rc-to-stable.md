# TODO-147: Replace aead RC Dependency with Stable Release

## Status
**COMPLETED**

## Completion Note
No stable 0.6.0 release exists yet (RustCrypto AEAD family remains in RC). Updated from `0.6.0-rc.1` to `0.6.0-rc.10` (latest RC). The dependency is optional and not directly imported by any source file. When 0.6.0 stable ships, a simple version bump in Cargo.toml will suffice.

## Severity
**CRITICAL**

## Context
The project depends on `aead = "0.6.0-rc1"`, a release candidate version. RC crates are pre-release and may introduce breaking API changes before the stable `0.6.0` release. Using RC dependencies in production code creates fragility - the API surface is not guaranteed stable, and downstream crates may not be compatible.

- `Cargo.toml`: `aead = "0.6.0-rc1"` in `[dependencies]`
- All crypto-related source files that import from the `aead` crate

## Root Cause
The `aead` 0.6.0 stable was likely not yet available when this dependency was added, and the RC was pulled in for early access to new features or API changes. The dependency was never revisited after the RC period.

## Fix Plan
1. Check crates.io for the current stable release of `aead`: `cargo search aead`
2. If `aead 0.6.0` stable is available:
   - Update `Cargo.toml` to `aead = "0.6.0"`
   - Verify API compatibility (RC to stable may have minor changes)
3. If `aead 0.6.0` stable is NOT yet available:
   - Pin to the latest stable release (likely `0.5.x`)
   - Adapt any API usage that differs between 0.5.x and 0.6.0-rc1
   - Document the intent to upgrade to 0.6.0 when stable
4. Check all related RustCrypto crates for version alignment (`aes-gcm`, `chacha20poly1305`, etc.) - they often need to be on matching major versions
5. Run `cargo build`, `cargo clippy -- -D warnings`, `cargo test`
6. Verify all crypto operations still function correctly

## Acceptance Criteria
- No RC (release candidate) dependencies in `Cargo.toml`
- All `aead` trait implementations compile against the stable version
- All crypto tests pass
- `cargo clippy -- -D warnings` clean
- `cargo audit` shows no advisories for the aead dependency

## Dependencies
- RustCrypto ecosystem version alignment (aes-gcm, chacha20poly1305, etc. must be compatible)
- Crypto test suite must pass end-to-end

## Affected Files
- `Cargo.toml` (version bump)
- `Cargo.lock` (will update automatically)
- `src/crypto.rs` (if API changed between RC and stable)
- `src/optimize/crypto/mod.rs` (if API changed)
- `src/optimize/crypto/planner.rs` (if API changed)
- Any file importing `aead` traits or types
