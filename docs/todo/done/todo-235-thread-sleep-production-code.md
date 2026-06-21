# TODO-235: std::thread::sleep in Production Synchronous Code Paths

## Severity: HIGH

## Problem

Three locations use `std::thread::sleep` in production synchronous functions that may be called from contexts where blocking is harmful:

### 1. Stealth TLS Cover Jitter
`src/stealth.rs:892`:
```rust
std::thread::sleep(std::time::Duration::from_micros(jitter));
```
Function: `generate_fake_crypto_frame()` (sync, line 786)
Called from: `next_crypto_frame()` -> stealth padding hot path
Impact: Blocks the calling thread for up to N microseconds per fake crypto frame

### 2. TLS Profile Application Jitter
`src/qftls.rs:1232`:
```rust
std::thread::sleep(jitter);
```
Function: `apply_profile_to_config()` (sync, line 1227)
Impact: Blocks during TLS profile application, delays handshake

### 3. Handshake Polling Loop
`src/engine/engine.rs:872`:
```rust
std::thread::sleep(Duration::from_millis(25));
```
Function: `connect()` (sync, line 832)
Impact: Polling loop sleeps 25ms between handshake completion checks, blocking the entire thread

## Risk

While these are synchronous functions (not `async fn`), they block OS threads. If called from a Tokio runtime context (via `spawn_blocking` or accidentally from an async task), they starve the thread pool. Even in purely sync contexts, blocking threads for timing jitter is wasteful compared to async alternatives.

## Fix

### Option A: Make Async (Preferred for engine.rs)
1. `engine.rs:872`: Replace polling loop with `tokio::time::sleep` + async handshake notification
2. Use a `tokio::sync::Notify` or channel to signal handshake completion instead of polling

### Option B: Accept Sync Sleep (Acceptable for jitter)
3. `stealth.rs:892` and `qftls.rs:1232`: If sub-millisecond jitter is intentional for timing obfuscation, document why `thread::sleep` is chosen over `tokio::time::sleep`
4. Add comments: `// Intentional sync sleep for timing-channel mitigation - do not convert to async`

### Either way:
5. Audit call chains to ensure none of these sync functions are called from async contexts without `spawn_blocking`

## Affected Files

- `src/stealth.rs:892`
- `src/qftls.rs:1232`
- `src/engine/engine.rs:872`

## Verification

- No `thread::sleep` inside async functions or Tokio task contexts
- `cargo clippy` passes
- Handshake timing unchanged or improved
