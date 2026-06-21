# TODO-276: tokio::spawn Fire-and-Forget in Reality Proxy

## Severity: HIGH

## Source
Cross-model forensic audit (2026-03-22). Found by 2/5 models, verified at src/reality.rs:123.

## Problem
`tokio::spawn(async move { ... })` at line 123 discards the JoinHandle. Consequences:
- Orphan tasks on shutdown (no graceful cancellation)
- Silent failures if spawned task panics
- No error propagation to parent

`MAX_SESSIONS = 10_000` (line 19) provides a cap, but reached-cap behavior just rejects new sessions without graceful degradation.

## Fix
1. Store JoinHandles in a `JoinSet` or `Vec<JoinHandle<()>>`
2. On shutdown: `join_set.shutdown().await` or iterate handles
3. Optionally: log errors from failed tasks via `JoinHandle::await`

```rust
let handle = tokio::spawn(async move { ... });
self.active_tasks.push(handle);
```

## Verification
- Graceful shutdown test: spawn tasks, shutdown, verify all complete
- Error propagation test: task panic is logged
