# TODO-247: Deterministic Session Cleanup in Reality Proxy

## Severity: MEDIUM

## Context
`src/reality.rs:71-73` uses `rand::random::<u8>() < 10` (~3.9% probability) to decide whether to run session cleanup. Under sustained high load, cleanup may not trigger often enough, allowing the session HashMap to grow unboundedly. Under low load, it triggers unnecessarily. This is a correctness concern, not just performance.

## Desired Outcome
- Replace probabilistic cleanup with a deterministic approach: either a periodic timer-based sweep (e.g., every 60 seconds) or a capacity-triggered eviction (e.g., when entries exceed a threshold).
- Add a TTL for reality proxy sessions so stale entries are always removed.
- Consider using an LRU cache or similar data structure with built-in eviction.

## Files
- `src/reality.rs` (lines ~65-80)

## Completion Criteria
- Session cleanup is deterministic and bounded.
- No HashMap can grow unboundedly under any load pattern.
- `cargo test` passes, clippy clean.
