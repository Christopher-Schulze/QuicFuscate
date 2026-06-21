---
id: TODO-357
title: "CONTRIBUTING.md says "Rust stable (latest)" instead of pinned version"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
resolved: 2026-03-27
---

# TODO-357: CONTRIBUTING.md says "Rust stable (latest)" instead of pinned version


## Problem
`docs/CONTRIBUTING.md` line 42 states "Rust stable (latest)" as prerequisite.
The project pins Rust 1.93.0 in `rust-toolchain.toml`. Contributors following
"latest" may use a different toolchain than CI, causing confusing failures.

## Fix Plan
1. Edit CONTRIBUTING.md line 42: change "Rust stable (latest)" to "Rust 1.93.0 stable (pinned in rust-toolchain.toml)"
2. Verify no other version references need updating

## Files to Modify
- docs/CONTRIBUTING.md