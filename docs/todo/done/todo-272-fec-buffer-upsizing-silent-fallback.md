# TODO-272: FEC Buffer Upsizing Silent Fallback

## Severity: CRITICAL

## Source
Cross-model forensic audit (2026-03-22). Found by MiniMax M2.7 (Kilocode), verified against code.

## Problem
In `src/fec/mod.rs` lines 1270-1284, when FecPacket needs a larger buffer:
- If allocation fails: `.Err(_) => Some(d)` returns the ORIGINAL undersized buffer
- But `data_len` may already be set to the LARGER value
- Result: `data_len > d.len()` - out-of-bounds read when `to_raw()` or `to_stream_raw()` serializes

## Fix
Option A: On allocation failure, truncate `data_len` to `d.len()`:
```rust
Err(_) => {
    self.data_len = d.len();
    Some(d)
}
```

Option B: Return `None` on allocation failure (propagate error):
```rust
Err(_) => None
```

Option B is safer - callers already handle `None`.

## Verification
- Unit test: force allocation failure, verify no OOB
- cargo test GREEN, clippy GREEN
