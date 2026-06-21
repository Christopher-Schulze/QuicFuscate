# TODO-271: FEC emitted_ids HashSet Unbounded Growth

## Severity: CRITICAL

## Source
Cross-model forensic audit (2026-03-22). Found by MiniMax M2.7 (Kilocode), verified against code.

## Problem
In `src/fec/mod.rs`, the `emitted_ids: HashSet<u64>` (line ~3044) grows without bound:
- Line ~3408: `self.emitted_ids.insert(p.id)` - inserts on every emitted packet
- `emitted_order: VecDeque` has a cap of 4096 entries
- But `emitted_ids` HashSet has NO corresponding pruning when `emitted_order.pop_front()` fires

Over long-lived connections with high packet throughput, this HashSet will consume unbounded memory.

## Fix
When `emitted_order` evicts old entries via `pop_front()`, also remove the evicted ID from `emitted_ids`:

```rust
if self.emitted_order.len() >= 4096 {
    if let Some(old_id) = self.emitted_order.pop_front() {
        self.emitted_ids.remove(&old_id);
    }
}
```

## Verification
- Unit test: emit >4096 packets, assert `emitted_ids.len() <= 4096`
- cargo test GREEN, clippy GREEN
