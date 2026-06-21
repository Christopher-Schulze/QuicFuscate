---
id: TODO-401
title: Stealth-on vs stealth-off CI regression
severity: MEDIUM
phase: C
priority: P2
status: DONE
created: 2026-06-05
---

# TODO-401: Stealth-On vs Stealth-Off Regression Gate

## Problem

No automated measurement of stealth tax (padding + timing) on throughput/latency. Optimizations may regress stealth performance balance unknowingly.

## Acceptance

- CI job or PR bench compares same workload stealth on/off
- Warn threshold documented (e.g. 15% throughput delta)
- Does not touch UI

## Fix Plan

1. Extend TODO-399 bench with stealth flags
2. Add critcmp or custom comparator in `bench-ci-regression.sh`
3. `continue-on-error` on PR initially, tighten later

## Files

- `.github/workflows/ci.yml` (benchmarks job)
- `scripts/benchmarks/bench-ci-regression.sh`

## Depends

- TODO-399
