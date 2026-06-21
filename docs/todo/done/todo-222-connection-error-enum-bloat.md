# TODO-222: ConnectionError Enum 44-Variant Bloat and Duplicates

## Severity: HIGH

## Problem

`src/lib.rs` defines a `ConnectionError` enum with 44 variants. Several are semantic duplicates:

- `TransportError(String)` (line ~30) and `Transport(String)` (line ~52) - same meaning
- `CryptoError` and `CryptoFail` - overlapping semantics
- `FlowControlError` and `FlowControl` - same concept

This creates confusion about which variant to use, makes match arms inconsistent, and increases cognitive load for contributors.

## Impact

- Code authors pick random variants for the same error class
- Match arms must cover both duplicates
- Error messages are inconsistent across the codebase
- Makes refactoring and error handling harder

## Fix

1. Audit all 44 variants and identify semantic duplicates
2. Choose canonical names for each error class (prefer the more descriptive name)
3. Replace all usages of deprecated variants with canonical ones
4. Remove duplicate variants
5. Target: reduce to ~25-30 well-defined variants
6. Consider grouping related errors into nested enums if appropriate

## Affected Files

- `src/lib.rs` - enum definition
- All files that construct or match on `ConnectionError` variants
- Ripple through: transport/, implementations/, engine/, brain.rs, stealth.rs, etc.

## Verification

- `cargo build` passes with no errors
- `cargo clippy` passes
- `cargo test` passes - existing error handling behavior unchanged
- Exhaustive match arms compile without warnings
