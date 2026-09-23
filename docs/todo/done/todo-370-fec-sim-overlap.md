---
id: TODO-370
title: "Remove fec_sim overlap between test-fec-simulation.sh and test-fec-e2e-loss.sh"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
resolved: 2026-09-24
schema_exception: missing_depends_on
---

# TODO-370: Remove fec_sim overlap between test-fec-simulation.sh and test-fec-e2e-loss.sh


## Problem
When `test-fec-all.sh` runs both `test-fec-simulation.sh` and `test-fec-e2e-loss.sh`:
- `test-fec-simulation.sh` lines 199-207 runs fec_sim for modes normal/streaming/extreme at loss=0.15
- `test-fec-e2e-loss.sh` runs fec_sim at multiple loss levels including 0.15

This means the same fec_sim binary is exercised twice with overlapping parameters,
wasting CI time.

## Fix Plan
Option A: Remove the fec_sim invocation from test-fec-simulation.sh (lines 199-207),
since test-fec-e2e-loss.sh is the dedicated fec_sim runner with more comprehensive
loss level coverage.

Option B: Add a flag to test-fec-simulation.sh to skip fec_sim when called from
test-fec-all.sh (e.g., --skip-e2e).

Recommendation: Option A is cleaner.

## Files to Modify
- scripts/tests/suites/test-fec-simulation.sh

## Closure (2026-09-24)

`test-fec-simulation.sh` now runs the focused FEC selection test across its
configuration matrix and does not invoke the `fec_sim` example. The model-loss
example runs only in `test-fec-e2e-loss.sh`; `test-fec-all.sh` dispatches that
suite separately. Source inspection verifies the overlap is gone. The old
library-test count was not evidence for this disposition, and no new Rust
execution was needed for this historical script-ownership correction.
