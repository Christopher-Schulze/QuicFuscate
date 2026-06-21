---
id: TODO-386
title: "Add tests for server/fsutil.rs (50 LOC, 0 tests)"
severity: "MEDIUM (coverage)"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "Coverage-gap per module — replaced by single cargo-tarpaulin baseline run"
---

# TODO-386: Add tests for server/fsutil.rs (50 LOC, 0 tests)


## Problem
`src/implementations/server/fsutil.rs` provides `atomic_write_file()` - a safety-critical
function that writes files atomically (write-to-temp + rename). Used for persistent
state storage. Has ZERO test coverage from any source.

## Fix Plan
Target: +5 tests:
1. Happy path: write file, verify content
2. Overwrite: atomic replacement preserves new content
3. Directory creation: handles missing parent dirs (or errors gracefully)
4. Permissions: file has correct permissions after write
5. Concurrent safety: two writes don't corrupt (if applicable)

## Files to Modify
- src/implementations/server/fsutil.rs (add #[cfg(test)] module)