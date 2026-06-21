# TODO-226: std::env::set_var After Tokio Runtime Start

## Severity: HIGH

## Problem

`src/main.rs:1075` calls `std::env::set_var("RUST_LOG", ...)` after the Tokio runtime has already been started via `runtime.block_on()` at line ~1064.

Since Rust 1.66, `std::env::set_var` is documented as unsafe in multi-threaded contexts because it modifies process-global state without synchronization. The Tokio runtime spawns multiple worker threads, making this a data race.

## Impact

- Undefined behavior per Rust safety model (data race on process environment)
- Could cause crashes, incorrect env reads, or silent corruption on other threads
- Rust may make `set_var` an unsafe fn in a future edition
- Currently only triggers MIRI warnings, not compiler errors, but is technically UB

## Fix

1. Move `std::env::set_var("RUST_LOG", ...)` BEFORE `runtime.block_on()` / before Tokio runtime creation
2. If the log level needs to be dynamic: use `env_logger::Builder` or `tracing_subscriber` filter reload instead of env mutation
3. Audit all other `set_var` calls for same pattern

## Affected Files

- `src/main.rs:1075` - the offending set_var call
- Potentially other set_var calls if they exist after runtime start

## Verification

- `cargo clippy` passes
- Grep for `set_var` confirms all calls are before multi-threaded runtime start
- Existing tests pass
