# TODO 73: FEC Constructor Ambient-State Drift

## Scope
- `src/fec.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- `AdaptiveFec::new()` mixes config with env/global/thread-pool/CPU-profile side effects.
  - Evidence: `src/fec.rs:4698`, `:4700`, `:4708`, `:4711`, `:4751`, `:4763`

## Objectives
- Make FEC construction more explicit and deterministic.

## Work Breakdown
- [x] Inventory ambient inputs and hidden side effects.
- [x] Split pure policy derivation from resource/global initialization.
- [x] Add deterministic tests for the retained ambient inputs.

## Acceptance Criteria
- [x] FEC behavior can be reasoned about primarily from explicit config.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Completed. `AdaptiveFec::new()` now separates explicit global-resource setup, constructor ambient snapshots, and runtime plan derivation. The retained ambient seams are named and isolated as `FecComputeProfile` plus `FecObserverProfilePolicy`/`FecObserverPlatformHints`, and deterministic regression tests lock in both explicit override precedence and instance-owned snapshot behavior.
