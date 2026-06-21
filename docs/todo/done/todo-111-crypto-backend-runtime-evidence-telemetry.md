# TODO 111: Crypto Backend Runtime Evidence Telemetry

## Scope
- runtime backend selection visibility
- retained AEGIS width evidence
- MORUS selection evidence
- exported metrics for planner decisions

## Problem Statement
- The planner is consistent and tested.
- What is still weaker than ideal is runtime observability:
  - which backend families are actually chosen
  - how often
  - under what traffic profile

## Desired End State
- Runtime telemetry can show real backend selection behavior.
- The repo can justify retained X4/X8 complexity with runtime evidence, not only code comments and tests.

## Current Truth Snapshot
- Planner already increments some plan-decision counters.
- Exported telemetry exists.

## Architecture Gap
- Current metrics are useful, but not yet shaped as a reviewer-facing evidence layer for retained backend decisions.

## Execution Plan

### Phase 1: Counter Audit
- Inventory current planner/backend counters and identify gaps.

### Phase 2: Export Tightening
- Export counters in a form that clearly answers:
  - how often `Aegis128L`
  - how often `Aegis128X4`
  - how often `Aegis128X8`
  - how often `Morus1280_128`

### Phase 3: Documentation Sync
- Document how to interpret these counters and how they support retained-backend decisions.

## Acceptance Criteria
- [x] Runtime telemetry exposes retained backend selection clearly.
- [x] The exported metrics are reviewer-usable, not just implementation leftovers.

## Validation Matrix
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`
- telemetry export smoke checks

## Final Status
- Completed.
- Runtime telemetry now distinguishes:
  - planner choices for `Aegis128X4`
  - planner choices for `Aegis128X8`
  - actual built AEAD backend selections for:
    - `Aegis128L`
    - `Aegis128X4`
    - `Aegis128X8`
    - `Morus1280_128`
- Exported reviewer-facing metrics now include:
  - `quicfuscate_plan_select_x4_total`
  - `quicfuscate_plan_select_x8_total`
  - `quicfuscate_data_aead_backend_aegis_l_total`
  - `quicfuscate_data_aead_backend_aegis_x4_total`
  - `quicfuscate_data_aead_backend_aegis_x8_total`
  - `quicfuscate_data_aead_backend_morus_total`
