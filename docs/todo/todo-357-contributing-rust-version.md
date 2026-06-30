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
The project uses the Rust stable channel in `rust-toolchain.toml`. Contributors following
"latest" may use a different toolchain than CI, causing confusing failures.

## Fix Plan
1. Edit CONTRIBUTING.md line 42: document that Rust stable is selected by `rust-toolchain.toml`
2. Verify no other version references need updating

## Files to Modify
- docs/CONTRIBUTING.md
