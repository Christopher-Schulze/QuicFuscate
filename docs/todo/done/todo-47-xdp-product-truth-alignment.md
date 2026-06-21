# TODO 47: XDP Product Truth Alignment

## Scope
- XDP support contract alignment across:
  - Runtime behavior (`src/optimize.rs`, `src/core.rs`, `src/main.rs`)
  - Transport modules (`src/transport/xdp.rs`)
  - Docs (`README.md`, `docs/DOCUMENTATION.md`)
  - Config/env semantics (`QUICFUSCATE_FASTPATH=xdp`)

## Problem Statement (Audit Evidence, 2026-03-05)
- Runtime capability reports XDP unsupported (`is_supported() -> false`), which disables optimization-manager XDP path.
  - Evidence: `src/optimize.rs:3563`, `:3028`, `:3075`
- Core still attempts XDP socket creation through optimization manager interface, creating semantic confusion.
  - Evidence: `src/core.rs:212`, `:255`
- CLI/runtime comments say "XDP removed", while docs and feature text still present XDP compatibility mode.
  - Evidence: `src/main.rs:1000`, `:1110`, `:1650`; `README.md:30`, `:126`; `docs/DOCUMENTATION.md:747`

## Objectives
- Decide single XDP policy: supported, compatibility-only, or deprecated/removed.
- Align runtime behavior, user-visible surface, and documentation to the same policy.
- Prevent future drift between docs and code.

## Work Breakdown
### A. Policy Decision
- [x] Decide XDP state for current release branch (active/deprecated/removed). [x] 2026-03-05
- [x] Record rationale and constraints (platform support, maintenance burden, risk). [x] 2026-03-05

### B. Code Alignment
- [x] Align `OptimizationManager` capability reporting and actual behavior with policy. [x] 2026-03-05
- [x] Align `core` and `main` XDP code paths/comments with policy. [x] 2026-03-08
- [x] Align `QUICFUSCATE_FASTPATH=xdp` behavior and log semantics with policy. [x] 2026-03-05

### C. Documentation Alignment
- [x] Update README fastpath claims to match runtime reality. [x] 2026-03-05
- [x] Update `docs/DOCUMENTATION.md` XDP sections and configuration descriptions. [x] 2026-03-05
- [x] Add explicit status label for XDP in feature matrix (`active`, `compat-only`, `deprecated`). [x] 2026-03-08

### D. Regression Guards
- [x] Add tests that assert support-state contract consistency. [x] 2026-03-05
- [x] Add a docs/code contract check for XDP support statements. [x] 2026-03-05

## Acceptance Criteria
- [x] One unambiguous XDP status is reflected consistently in code, logs, and docs. [x] 2026-03-08
- [x] `QUICFUSCATE_FASTPATH=xdp` semantics are explicit and tested. [x] 2026-03-05
- [x] CI/docs checks fail on future XDP contract drift. [x] 2026-03-08

## Deliverables
- [x] Updated runtime and documentation XDP contract. [x] 2026-03-08
- [x] Support-state regression tests/checks. [x] 2026-03-05
- [x] Clear XDP status entry in docs. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-05: XDP policy fixed to `compat-only` for current branch. `FastpathMode::Xdp` now maps to UDP/io_uring behavior, runtime logs explicitly describe compatibility alias semantics, and README/docs wording has been aligned to the same contract.
- 2026-03-05: Added compatibility regression test coverage in `src/interface.rs::fastpath_mode_xdp_is_compat_alias_to_uring_path`.
- 2026-03-08: Added explicit XDP status labels to README and `docs/DOCUMENTATION.md`, and closed the remaining TODO after confirming that runtime/config/comments/docs all reflect the same `compat-only` contract.
