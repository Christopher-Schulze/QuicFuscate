---
id: TODO-376
title: "Test simd-selfcheck on macOS/Windows in CI feature-matrix"
severity: "LOW"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-376: Test simd-selfcheck on macOS/Windows in CI feature-matrix


## Problem
The `simd-selfcheck` feature is only tested on `ubuntu-latest` in both `ci.yml`
feature-matrix and `clippy-matrix.yml`. If SIMD selfcheck has cross-platform code
paths (e.g., ARM NEON on macOS), failures on non-Linux would be undetected.

## Fix Plan
1. Add `simd-selfcheck` to the macOS feature combo in ci.yml feature-matrix job
2. If Windows has SIMD support: add there too
3. Verify the feature compiles on all platforms before adding

## Files to Modify
- .github/workflows/ci.yml