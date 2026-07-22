---
id: TODO-358
title: "Remove 4 dead PQ trait methods from qftls.rs"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
defer_reason: "Dead-code — cargo dead / cargo udeps covers this"
resolved: 2026-07-22
---

# TODO-358: Remove 4 dead PQ trait methods from qftls.rs


## Problem
Post-quantum code was deleted in TODO-286, but 4 dead trait methods remain on
`QuicTlsProvider` in `src/qftls.rs` lines 615-641:
- `supports_pq_hybrid()` -> returns false
- `pq_hybrid_public_key()` -> returns None
- `pq_hybrid_complete_exchange()` -> returns Err
- `pq_hybrid_initiate()` -> returns Err

These are default no-ops. The `pq` feature is commented out in Cargo.toml (line 120).
No code calls these methods. They are pure dead interface surface.

Also: `src/lib.rs` line 21 doc string says "...and post-quantum support." - stale.
Also: Comment tombstones at qftls.rs:896, :1801 and crypto/mod.rs:347, :904-906.

## Fix Plan
1. Delete the 4 trait methods from `QuicTlsProvider` (qftls.rs:615-641)
2. Remove any `impl` blocks that override these methods (search all implementors)
3. Remove "and post-quantum support" from lib.rs:21 doc string
4. Remove tombstone comments at qftls.rs:896, :1801 and crypto/mod.rs:347, :904-906
5. cargo build + cargo test to verify nothing breaks

## Files to Modify
- src/qftls.rs
- src/lib.rs
- src/crypto/mod.rs

## Resolution

Verified during TODO-521 reconciliation: all four PQ trait methods, the stale public post-quantum claim, and the listed PQ tombstone comments are absent. Current Rust and Clippy gates pass.
