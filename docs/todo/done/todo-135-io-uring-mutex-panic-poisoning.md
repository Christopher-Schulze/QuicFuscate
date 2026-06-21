# TODO-135: io_uring Mutex Panic Poisoning Silently Ignored

## Status
**COMPLETED**

## Completion Note
Replaced all `unwrap_or_else(|e| e.into_inner())` patterns with proper `map_err` + `?` error propagation returning `io::Error` with descriptive messages. Updated `IoUringRegistry::get_or_create` to return `io::Result<Option<...>>` and `remove` to return `io::Result<()>`. Callers propagate errors correctly via the `?` operator.

## Severity
**MEDIUM**

## Context
In `src/transport/uring.rs:55`, a poisoned mutex is silently recovered from:

```rust
.unwrap_or_else(|e| e.into_inner())
```

If a thread panics while holding this mutex lock, the mutex becomes poisoned. The current code extracts the inner value and continues as if nothing happened. However, the data protected by the mutex may be in an inconsistent/corrupt state since the previous holder panicked mid-operation.

This could lead to:
- Sending corrupted packets
- Using stale or partially-updated io_uring state
- Undefined behavior if the corrupt state is passed to kernel syscalls

## Root Cause
Convenience pattern used instead of proper error handling. Mutex poisoning is a signal that protected data may be corrupt, and silently ignoring it defeats the purpose of Rust's poisoning mechanism.

## Fix Plan
1. Replace `unwrap_or_else(|e| e.into_inner())` with proper error propagation
2. When mutex is poisoned:
   - Log an error with `tracing::error!` including context about which mutex and what operation
   - Return an `Err` to the caller indicating the io_uring subsystem is in a failed state
3. Callers should handle this error by:
   - Attempting to re-initialize the io_uring instance, OR
   - Falling back to the sendmmsg path, OR
   - Shutting down the connection gracefully
4. Add a comment explaining why poisoned mutex recovery is not safe here
5. Consider whether `parking_lot::Mutex` (which doesn't poison) is more appropriate if the protected data can tolerate concurrent access after a panic

## Acceptance Criteria
- Poisoned mutex results in error propagation, not silent continuation
- Error is logged with sufficient context for debugging
- Callers handle the error gracefully (fallback or shutdown)
- No silent use of potentially corrupt io_uring state

## Dependencies
- Error type for uring module must support this failure mode
- Callers in transport layer must handle the new error variant

## Affected Files
- `src/transport/uring.rs`
- `src/transport/mod.rs` (error type)
- Callers of the uring send/recv functions
