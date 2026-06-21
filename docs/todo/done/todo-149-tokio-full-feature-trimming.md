# TODO-149: Trim tokio "full" Feature to Specific Features

## Status
**COMPLETED**

## Severity
**LOW**

## Context
The project uses `tokio = { features = ["full"] }` which enables every tokio feature: rt, rt-multi-thread, macros, sync, time, net, io-util, io-std, signal, process, fs, test-util, tracing. Many of these may be unused, resulting in unnecessary compile time and larger binary size.

- `Cargo.toml`: `tokio` dependency with `features = ["full"]`

## Root Cause
Using `"full"` is the quickest way to get started with tokio and avoids feature-flag debugging during development. It was never trimmed down to only the required features after the implementation stabilized.

## Fix Plan
1. Remove `"full"` from tokio features in `Cargo.toml`
2. Start with a minimal set: `["rt-multi-thread", "macros"]`
3. Attempt `cargo build` - collect all compilation errors related to missing tokio features
4. Add features one at a time based on actual usage:
   - `net` - if using `TcpListener`, `UdpSocket`, etc.
   - `io-util` - if using `AsyncReadExt`, `AsyncWriteExt`
   - `sync` - if using `Mutex`, `RwLock`, `Semaphore`, `mpsc`
   - `time` - if using `sleep`, `interval`, `timeout`
   - `signal` - if handling OS signals
   - `process` - if spawning child processes
   - `fs` - if using async file operations
   - `io-std` - if using `stdin`/`stdout`/`stderr`
5. Repeat until `cargo build` succeeds with the minimal feature set
6. Run `cargo test` to verify no runtime feature-gating issues
7. Compare binary size before and after: `ls -la target/release/quicfuscate`

## Acceptance Criteria
- tokio features explicitly listed in Cargo.toml (no `"full"`)
- Only actually-used features enabled
- `cargo build` and `cargo test` pass
- Binary size reduction documented (expected 5-15% reduction)
- `cargo clippy -- -D warnings` clean

## Dependencies
- None - purely a build configuration change

## Affected Files
- `Cargo.toml` (tokio features list)
- `Cargo.lock` (may update if feature changes affect resolved versions)
