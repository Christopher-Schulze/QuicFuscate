# TODO-246: Replace std::process::exit() in Library Code

## Severity: HIGH

## Context
`src/stealth.rs:1333` calls `std::process::exit(1)` inside a `LazyLock` initializer for `DOH_RUNTIME`. If the Tokio runtime fails to build, the entire process terminates with no chance for recovery. This is hostile to embedding scenarios (Tauri desktop app) where the host process should handle errors gracefully. Additionally, `src/stealth.rs:1326-1327` hard-codes `worker_threads(4)` for the DoH runtime, which is inappropriate for a library.

## Desired Outcome
- Replace `std::process::exit(1)` with `Result` propagation or a fallback that disables DoH without killing the process.
- Make the DoH runtime thread count configurable or derived from available cores.
- Embedding clients (Tauri) should survive a DoH initialization failure with degraded functionality (no DoH) rather than a crash.

## Files
- `src/stealth.rs` (lines ~1326-1340)

## Completion Criteria
- No `std::process::exit()` calls remain in library code (src/).
- DoH runtime failure results in a logged warning and disabled DoH, not a process exit.
- `cargo test` passes, clippy clean.
