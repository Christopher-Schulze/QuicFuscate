# TODO-165: CryptoManager Dead Code Removal

## Status
**COMPLETED**

## Completion Note
Investigation found that `CryptoManager` is NOT dead code. It is actively instantiated and used by: `StealthManager` (stealth.rs:4447, 4490, 4498, 4613), `CoreConnection` (core.rs:201, 253), client subsystems (subsystems.rs:36), and multiple tests (rt-security-suite, rt-probe-detection, stealth_mode_matrix). Methods use `OsRng.fill_bytes()` for real CSPRNG key generation - the original todo description claiming `vec![0u8; length]` return was incorrect. Added documentation comments explaining the struct's purpose and active usage sites.

## Severity
**HIGH**

## Context
The `CryptoManager` struct in `src/crypto.rs` (lines 3960-4009) contains methods that return placeholder/dummy data rather than performing real cryptographic operations. This dead code is misleading and a potential security concern - it could be mistakenly used, returning zero-filled keys.

- `src/crypto.rs:3960-4009`: `CryptoManager` struct definition and implementation
- `get_obfuscation_key()`: Returns `vec![0u8; length]` - a zero-filled key (security hazard)
- `pq_keypair()`: Returns empty vectors for both public and secret keys
- Real cryptographic operations are performed via `Aegis128L` and `MorusAead` implementations directly
- `CryptoManager` is never instantiated anywhere in the codebase

## Root Cause
Likely a scaffold/prototype struct that was superseded by the direct AEAD implementations but never cleaned up. The placeholder return values confirm it was never completed or used in production paths.

## Fix Plan
1. Verify `CryptoManager` is truly never instantiated: search all `CryptoManager::new`, `CryptoManager {`, and any trait implementations
2. Check for any references in tests, benchmarks, or examples
3. Remove the entire `CryptoManager` struct, its `impl` block, and any associated types
4. Run `cargo build` to confirm no compilation errors
5. Run `cargo test` to confirm no test breakage
6. Update `docs/MAP.md` to remove any `CryptoManager` references

## Acceptance Criteria
- `CryptoManager` struct completely removed from `src/crypto.rs`
- No placeholder/dummy cryptographic key generation exists in codebase
- `cargo build` and `cargo test` pass cleanly
- No references to `CryptoManager` remain anywhere in the codebase

## Dependencies
- None

## Affected Files
- `src/crypto.rs` (remove CryptoManager)
- `docs/MAP.md` (update if referenced)
