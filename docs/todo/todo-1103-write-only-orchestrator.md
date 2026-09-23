---
id: TODO-1103
title: Remove the write-only deep orchestrator path
severity: MED
phase: M
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1055, TODO-1079]
---

# TODO-1103: Write-only deep orchestrator

## Why and evidence

TODO-1055 removed the H3 server-push scheduler and all its trigger
consumers. `src/brain/orchestrator.rs::DeepIntegrationOrchestrator` now
contains only `stealth_active`, `loss_rate`, `cpu_usage_percent`,
`memory_pressure`, and `bandwidth_bps` atomics with a write-only
`update_runtime_signals` method. Repository caller search finds initialization
and writes in `src/core/connection.rs` but no load/read of those atomics.
Under the optional Cargo `orchestrator` feature, each connection still
refreshes process CPU and memory through `sysinfo`, and the global
`OnceLock` remains live without influencing Brain, FEC, Reality or H3.
`docs/DOCUMENTATION.md` describes cross-signal heuristics and cover-traffic
coordination that this code no longer performs. The former orchestrator
integration test was deleted with its consumers.

## Target contract

- Confirm the complete runtime/feature/cfg and external public-API consumer
  map before removal. If no actual consumer exists, delete the write-only
  type, singleton, environment gate, process sampling, update calls and
  feature dependency. Keep the existing connection-local `StealthBrain`
  sensors, FEC hints and telemetry owners intact; do not create replacement
  heuristics simply to justify the feature.
- Preserve externally meaningful feature-selection compatibility only if a
  real downstream build contract requires it. A temporary empty feature
  alias must have a documented retirement point and must not claim to
  activate steering. No two policy owners or unused global state remain.
- `docs/DOCUMENTATION.md`, `docs/MAP.md`, CONTRIBUTING, Cargo feature
  descriptions, test-target required-features and suite scripts state the
  actual enabled behavior. Remove or replace tests that only prove writes to
  unused atomics with tests on the retained Brain/FEC signals and live
  outputs.

## Implementation and proof

- [ ] Search all in-repo callers, feature declarations, cfg paths, tests,
      scripts, README and docs for orchestrator references; inspect exported
      API/semver expectations before selecting the smallest removal path.
- [ ] Remove the unused production wiring and any obsolete test target
      atomically; retain `sysinfo` only where another real runtime owner
      still uses it. Validate default, no-default and all-feature builds
      without breaking the existing task gates.
- [ ] Prove, with a focused behavior test, that Brain/FEC/Reality signals
      still reach their actual consumers and that disabled/removed
      orchestrator sampling creates no process-refresh work.
- [ ] Correct historical TODO-1055 wording only where it describes current
      behavior; update canonical docs and feature matrix in one pass.

## Acceptance

- Zero write-only orchestrator atomics, global initialization and process
  refreshes remain in production. Retained Brain/FEC/Reality behavior and
  test gates pass with the declared feature sets.
- No current documentation or CLI output claims deep-orchestrator steering
  without a measured runtime consumer.
