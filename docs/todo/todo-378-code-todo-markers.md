---
id: TODO-378
title: "Review and resolve 7 TODO markers in Rust source code"
severity: "LOW"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
defer_reason: "Code TODO-markers — grep -rn TODO src/ is not a task"
resolved: 2026-07-22
---

# TODO-378: Review and resolve 7 TODO markers in Rust source code


## Problem
7 TODO/reference markers exist in src/:

1. `src/stealth/tests.rs:193` - "TLS Cover Tests (TODO-297)" - section header, tests exist
2. `src/stealth/mod.rs:864` - "SAFETY (cipher reinstallation - TODO-269 audit)" - open security audit item
3. `src/stealth/mod.rs:1364` - "DPI fingerprinting via cipher mismatch (TODO-288)" - rationale ref, resolved
4. `src/crypto/mod.rs:347` - "removed in TODO-286" - tombstone
5. `src/crypto/mod.rs:904-906` - "Post-Quantum Cryptography: removed in TODO-286" - tombstone
6. `src/qftls.rs:896` - "PQ hybrid key exchange removed in TODO-286" - tombstone
7. `src/qftls.rs:1801` - "PQ hybrid key exchange methods removed in TODO-286" - tombstone

Items 4-7 are tombstone comments for deleted PQ code (overlaps with TODO-358).
Item 2 (TODO-269) is an open security audit item that should be tracked.
Items 1, 3 are informational references to completed TODOs.

## Fix Plan
1. Items 4-7: Remove as part of TODO-358 (PQ cleanup)
2. Item 2 (TODO-269): Verify cipher reinstallation safety, then either resolve or keep
3. Items 1, 3: Leave as-is (informational, non-actionable)

## Files to Modify
- Covered by TODO-358 for items 4-7
- src/stealth/mod.rs for item 2 (independent review)

## Resolution

Scrapped during the exhaustive acceptance reconciliation because source marker count is not a deliverable. PQ tombstones are gone, informational task references are valid, and the remaining cipher-reinstallation security obligation moved to TODO-545.
