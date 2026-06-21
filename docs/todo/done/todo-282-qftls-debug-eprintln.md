# TODO-282: Debug eprintln! Statements in qftls.rs

## Severity: LOW

## Source
Cross-model forensic audit (2026-03-22). Found by 2/5 models, verified.

## Problem
`src/qftls.rs` lines 33-58 contain `eprintln!` for TLS debug output:
- Line 33: `eprintln!("[qftls] {:?} keychange={}", ...)`
- Line 39: `eprintln!("[qftls] {}", message)`
- Lines 45-48: `eprintln!("[qftls] hp mask0={:02x} ...")`

All are gated behind `if trace_tls_enabled()` (env var `QUICFUSCATE_TRACE_TLS=1`), so they don't fire in normal operation. However, they bypass the logging framework (log crate) and write directly to stderr.

## Fix
Replace `eprintln!` with `log::trace!`:
```rust
// Before
if trace_tls_enabled() {
    eprintln!("[qftls] {:?} keychange={}", ...);
}

// After
log::trace!("[qftls] {:?} keychange={}", ...);
```

The `log::trace!` macro is already filtered by log level, so the `trace_tls_enabled()` guard can be removed.

## Verification
- `QUICFUSCATE_TRACE_TLS=1 RUST_LOG=trace` still shows TLS debug output
- No eprintln! remaining in qftls.rs
- cargo test GREEN
