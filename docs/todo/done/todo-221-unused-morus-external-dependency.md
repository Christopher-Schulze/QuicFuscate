# TODO-221: Unused morus External Dependency

## Severity: MEDIUM

## Problem

`Cargo.toml:30` declares `morus = "0.1.3"` as an external dependency. However, `grep -r "morus::" src/` finds zero references. The project has its own complete MORUS-1280-128 implementation in `src/crypto.rs:591+` (`Morus1280State`, `MorusAead`).

## Impact

- Dead dependency weight in Cargo.lock (compile time, binary size negligible but pollutes dep tree)
- Confusion for auditors: two MORUS implementations, unclear which is active
- The external crate is unused but sits in the dependency list

## Fix

1. Remove `morus = "0.1.3"` from `[dependencies]` in `Cargo.toml`
2. Run `cargo check` to confirm no breakage
3. Verify the custom `Morus1280State` in `src/crypto.rs` is the sole MORUS implementation

## Affected Files

- `Cargo.toml` - remove dependency line

## Verification

- `cargo check` passes
- `cargo clippy --workspace --all-targets -- -D warnings` passes
- `grep -r "morus::" src/` still returns nothing
