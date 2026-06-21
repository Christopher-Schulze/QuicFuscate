---
id: TODO-371
title: "Remove redundant smoke-fec-quick.sh"
severity: "LOW"
phase: legacy
priority: legacy
status: SCRAP
created: 2026-03-27
backfilled: 2026-07-23
scrap_reason: "smoke-fec-quick.sh redundant — deleted in prior session"
---

# TODO-371: Remove redundant smoke-fec-quick.sh


## Problem
`scripts/benchmarks/smoke/smoke-fec-quick.sh` is a pure pass-through that does nothing
except call `bench-fec-simulation.sh --fast`. It adds its own output directory setup
which is immediately overridden by the --output-dir passthrough.

`bench-fec-all.sh --mode smoke` already does the same thing.

## Fix Plan
1. Check if smoke-fec-quick.sh is referenced anywhere else
2. If only called from bench-fec-all.sh: replace the call with direct invocation
   of bench-fec-simulation.sh --fast
3. Delete smoke-fec-quick.sh
4. Update MAP.md if it lists this file

## Files to Modify
- scripts/benchmarks/smoke/smoke-fec-quick.sh (delete)
- scripts/benchmarks/suites/bench-fec-all.sh (update reference)
- docs/MAP.md (if listed)