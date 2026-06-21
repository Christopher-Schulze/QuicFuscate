# TODO-148: Audit and Review md5 Crate Usage

## Status
**COMPLETED**

## Completion Note
MD5 is used exclusively in `src/engine/qkey.rs` for legacy QKey checksum backward compatibility. New QKeys use SHA-256 (`s256:` prefix). MD5 path is non-security: it validates a short data-integrity tag, not cryptographic authentication. Added explicit SAFETY comments at both usage sites (production code and test) documenting the non-security rationale. The `md5` crate is retained in Cargo.toml for this legacy compatibility path.

## Severity
**HIGH**

## Context
The `md5` crate is used in the project. MD5 is cryptographically broken - it is vulnerable to collision attacks, preimage attacks, and length extension attacks. It must never be used for any security-sensitive purpose (authentication, integrity verification, digital signatures, password hashing).

MD5 is acceptable ONLY for non-security checksums (e.g., cache keys, deduplication hashes, legacy protocol compliance) where collision resistance is not required.

- `Cargo.toml`: `md5` listed as a dependency
- All source files that import or use the `md5` crate

## Root Cause
MD5 was likely used for convenience (short hash output, simple API) without evaluating whether the use case requires cryptographic strength. Given that QuicFuscate is a security/obfuscation tool, any MD5 usage must be scrutinized carefully.

## Fix Plan
1. Grep the entire codebase for md5 usage:
   - `use md5`, `md5::compute`, `md5::Digest`, `md5::Context`
   - Any references in comments or documentation
2. For each usage site, classify as:
   - **Security-critical**: authentication, integrity, signatures, key derivation -> MUST replace with SHA-256 or BLAKE3
   - **Non-security**: cache keys, debug identifiers, legacy protocol compliance -> Document with explicit comment: `// SAFETY: MD5 used here for non-security checksum only, not for cryptographic integrity`
3. Replace all security-critical usages with `sha2::Sha256` or `blake3`
4. If all usages are replaced, remove `md5` from `Cargo.toml` entirely
5. If some non-security usages remain, add a code comment at each site and a note in documentation.md explaining the rationale
6. Run `cargo build`, `cargo clippy -- -D warnings`, `cargo test`

## Acceptance Criteria
- Every md5 usage site is either:
  - Replaced with a cryptographically secure hash (SHA-256/BLAKE3), OR
  - Explicitly documented as non-security with a safety comment
- No md5 usage for any security-sensitive operation
- If md5 crate remains in Cargo.toml, it is justified in documentation.md
- All tests pass
- `cargo clippy -- -D warnings` clean

## Dependencies
- `sha2` or `blake3` crate if replacements are needed (likely already in dependency tree)
- Understanding of each call site's security requirements

## Affected Files
- `Cargo.toml` (potential removal or justification)
- All `src/**/*.rs` files using `md5`
- `docs/documentation.md` (if non-security usage is retained, document rationale)
