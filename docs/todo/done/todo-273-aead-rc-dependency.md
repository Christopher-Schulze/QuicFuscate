# TODO-273: aead 0.6.0-rc.10 RC Dependency in Production

## Severity: HIGH

## Source
Cross-model forensic audit (2026-03-22). Found by Mimo V2 Pro, verified in Cargo.toml line 30.

## Problem
`Cargo.toml` line 30: `aead = { version = "0.6.0-rc.10", features = ["alloc"], optional = true }`

Release candidate in production dependency tree. RC versions may have breaking changes, incomplete APIs, or undiscovered bugs.

## Fix
- Monitor RustCrypto for aead 0.6.0 stable release
- When available: `cargo update -p aead`
- If stable is delayed: evaluate pinning to last known-good RC or downgrading to 0.5.x stable

## Notes
- This is tracked since TODO-147 which noted "completed - updated to rc.10"
- The RC has been stable in practice but is not semantically production-grade
- aead crate is optional (`optional = true`) - only pulled when specific features are enabled

## Verification
- `cargo build` after upgrade
- All crypto tests pass
