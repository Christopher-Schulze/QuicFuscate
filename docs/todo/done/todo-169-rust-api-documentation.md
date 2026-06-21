# TODO-169: Rust Public API Documentation

## Status
**PARTIAL** - Added `///` doc comments to all `pub mod` declarations in `src/lib.rs` and expanded `ConfigError` documentation in `src/engine/config.rs`. Remaining: doc comments for all pub structs/traits/functions across other modules, `#![warn(missing_docs)]` lint enforcement.

## Severity
**MEDIUM**

## Context
Public Rust APIs across `src/` lack `///` doc comments. Most public structs, traits, functions, and enums have no documentation, making the codebase difficult to understand for contributors and making `cargo doc` output unhelpful.

- `src/` modules: Majority of `pub` items have no doc comments
- No `#![deny(missing_docs)]` lint enabled
- `cargo doc --no-deps` produces sparse, uninformative output

## Root Cause
Documentation was deprioritized during rapid development. No lint enforcement for missing docs was configured.

## Fix Plan
1. Start with public API surface (items reachable from `lib.rs` exports):
   - `src/lib.rs` re-exports
   - Public structs and their fields
   - Public trait definitions and their methods
   - Public enum variants
   - Public function signatures
2. Then move to internal module-level documentation:
   - Module-level `//!` comments for each `src/*.rs` file
   - Key internal structs and functions
3. Add `#![warn(missing_docs)]` to `src/lib.rs` to catch future regressions
4. Verify with `cargo doc --no-deps` that output is useful
5. Priority order: `crypto.rs`, `transport.rs`, `stealth.rs`, `fec.rs`, `core.rs`, then remaining modules

## Acceptance Criteria
- All public structs, traits, enums, and functions have `///` doc comments
- Each `src/*.rs` module has a `//!` module-level doc comment
- `cargo doc --no-deps` produces comprehensive, navigable documentation
- `#![warn(missing_docs)]` enabled in `src/lib.rs`

## Dependencies
- None

## Affected Files
- `src/lib.rs`
- `src/crypto.rs`
- `src/transport.rs`
- `src/stealth.rs`
- `src/fec.rs`
- `src/core.rs`
- All other `src/*.rs` files
- All `src/*/` submodule files
