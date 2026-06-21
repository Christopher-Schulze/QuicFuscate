# TODO-281: engine.rs Polling Loop TODO

## Severity: MEDIUM

## Source
Cross-model forensic audit (2026-03-22). Verified at src/engine/engine.rs:903.

## Problem
Line 903: `// TODO: replace polling loop with async notification (Notify/channel)`
Lines 907-909: Loop with 25ms `tokio::time::sleep` polling for state changes.

This wastes CPU cycles (40 wakeups/second) when idle. Should use event-driven notification.

## Fix
Replace polling loop with `tokio::sync::Notify`:
```rust
let notify = Arc::new(tokio::sync::Notify::new());
// In state-change paths:
notify.notify_one();
// In monitoring loop:
notify.notified().await;
```

Or use `tokio::sync::watch` channel for state observation.

## Verification
- Engine state transitions still work
- CPU usage at idle drops measurably
- All engine tests pass
