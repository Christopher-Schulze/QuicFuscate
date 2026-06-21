# TODO-237: Barrel Exports in server/mod.rs

## Severity: LOW

## Problem

`src/implementations/server/mod.rs` lines 33-47 contain 10 re-exports, including 5 wildcard `pub use *` barrel exports:

```rust
pub use accept::*;
pub use ip_pool::*;
pub use limits::*;
pub use routing::*;
pub use session::*;
```

Plus 5 named re-exports for admin, admin_http, and metrics.

This violates the project convention against barrel exports and makes it hard to trace where symbols originate.

## Fix

1. Remove wildcard `pub use *` re-exports
2. Replace with explicit named imports at call sites: `use crate::implementations::server::accept::AcceptLoop;` instead of `use crate::implementations::server::AcceptLoop;`
3. Keep named re-exports only for the most commonly used public types if needed
4. Update all import paths across the codebase

## Affected Files

- `src/implementations/server/mod.rs` - remove barrel exports
- All files that import from `implementations::server` - update import paths

## Verification

- `cargo build` passes
- `cargo clippy` passes
- No unused import warnings
