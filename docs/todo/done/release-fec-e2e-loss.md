# Release Task: FEC E2E Validation Under Loss

## Scope
- Validate end-to-end FEC behavior under controlled packet loss with explicit acceptance thresholds.
- Convert current partial coverage into deterministic, reproducible checks suitable for release gating.

## Current State
- Completed on 2026-02-12:
  - Added `scripts/tests/suites/test-fec-e2e-loss.sh` with deterministic seeded runs and explicit pass/fail thresholds.
  - Extended `examples/fec_sim.rs` with deterministic seed input (`FEC_SIM_SEED`) and richer metrics (`kept_systematic_unique`, `source_coverage_unique`).
  - Wired the suite into `scripts/tests/utils/util-run-full-suite.sh`.
  - Documented the suite in `docs/DOCUMENTATION.md` and `docs/MAP.md`.

## Plan
1. Define canonical loss matrix:
   - Loss levels: `0%`, `2%`, `5%`, `10%`, `15%`, `20%`.
   - Burst patterns: random and bursty.
2. Add deterministic E2E runner with seeded scenarios.
3. Capture core metrics:
   - Recovery ratio.
   - Residual loss after decode.
   - Throughput delta.
   - Mode transition behavior in Auto FEC.
4. Set release thresholds and fail fast when violated.
5. Integrate into `scripts/tests/suites/` and document invocation in `docs/DOCUMENTATION.md`.

## Acceptance Criteria
- A single command executes the full loss matrix and returns non-zero on threshold regressions.
- Results are written under `scripts/out/tests/test-fec-e2e-loss-<timestamp>/`.
- CI/local runs produce stable pass/fail behavior with fixed seeds.

## Deliverables
- New/updated suite script in `scripts/tests/suites/`.
- Threshold table in docs.
- Runbook snippet for local verification.

## Verification
- `scripts/tests/suites/test-fec-e2e-loss.sh --fast` -> pass on this host.
- `bash -n scripts/tests/suites/test-fec-e2e-loss.sh` -> pass.
