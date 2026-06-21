# TODO-146: Replace Deprecated lazy_static with std::sync::OnceLock

## Status
**COMPLETED**

## Completion Note
Replaced all `lazy_static!` usage. In `stealth.rs`: migrated to `std::sync::LazyLock` (required for runtime-initialized Tokio runtime). In `telemetry.rs`: all statics used `const fn` constructors (`Counter::new()`, `AtomicU64::new()`, `SafeGauge::new()`), so converted to plain `static` declarations - zero overhead, no lazy init needed. Removed `lazy_static` from `Cargo.toml` dependencies.

## Severity
**CRITICAL**

## Context
The `lazy_static` crate is deprecated since Rust 1.70. The standard library now provides `std::sync::OnceLock` (stabilized in Rust 1.80) and `std::sync::LazyLock` (stabilized in Rust 1.80) as built-in replacements. The `once_cell` crate (which inspired the std additions) is also a valid intermediate step.

All `lazy_static!` macro invocations across the codebase must be identified and migrated.

- `Cargo.toml`: `lazy_static` listed as a dependency
- All source files using `lazy_static!` macro blocks

## Root Cause
Historical usage of `lazy_static` before Rust stabilized equivalent functionality in std. The crate was never migrated away from after std alternatives became available.

## Fix Plan
1. Grep the entire codebase for `lazy_static` usage: `lazy_static!` macro calls, `use lazy_static` imports, and `Cargo.toml` dependency entry
2. For each `lazy_static!` block, replace with the appropriate pattern:
   - `static REF: OnceLock<Type> = OnceLock::new();` with an init function, OR
   - `static REF: LazyLock<Type> = LazyLock::new(|| { ... });` for direct replacement (preferred, closest 1:1 mapping)
3. Remove `lazy_static` from `[dependencies]` in `Cargo.toml`
4. Remove any `#[macro_use] extern crate lazy_static;` declarations
5. Run `cargo build`, `cargo clippy -- -D warnings`, `cargo test` to verify
6. Verify no remaining references to `lazy_static` anywhere in the codebase

## Acceptance Criteria
- No `lazy_static` dependency in `Cargo.toml`
- No `lazy_static!` macro usage in any source file
- All replaced statics compile and function identically
- All tests pass
- `cargo clippy -- -D warnings` clean

## Dependencies
- Rust edition 2021 or later (already satisfied)
- Rust compiler >= 1.80 for `LazyLock` (verify current toolchain version)

## Affected Files
- `Cargo.toml` (dependency removal)
- All `src/**/*.rs` files containing `lazy_static!` blocks
- `Cargo.lock` (will update automatically)
