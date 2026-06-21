---
id: TODO-360
title: "Replace eprintln! with log::warn! in transport hot path"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-360: Replace eprintln! with log::warn! in transport hot path


## Problem
`src/transport/connection.rs` line 1298 uses `eprintln!` to log a peer MAX_DATA
violation in the hot packet processing path. This:
- Blocks on stderr (performance impact)
- Bypasses the structured logging system
- Is inconsistent with the rest of the codebase (which uses `log` crate)

## Fix Plan
1. Replace `eprintln!(...)` at connection.rs:1298 with `log::warn!(...)`
2. Verify `use log::warn;` is imported (or use `log::warn!` with full path)
3. Search for other eprintln! in non-test, non-binary code to catch similar issues

## Files to Modify
- src/transport/connection.rs