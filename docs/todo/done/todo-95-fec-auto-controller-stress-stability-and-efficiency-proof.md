# TODO 95: FEC Auto-Controller Stress, Stability, and Efficiency Proof

## Scope
- `AdaptiveFec` scenario proof
- clean-link efficiency
- escalation/de-escalation stability
- severe-loss survival behavior

## Problem Statement
- The FEC controller architecture is now target-first, but that architectural success still needs hard empirical proof.
- The critical questions are no longer shape but behavior:
  - does `Zero` stay effectively free on healthy links
  - does `Auto` avoid nervous thrash
  - does escalation preserve stability under hostile conditions
  - does `Fountain` only appear when it really earns its CPU cost

## Desired End State
- One measured answer for each major path class:
  - clean link
  - burst loss
  - reorder
  - fluctuating loss
  - high jitter
  - severe sustained loss
- Explicit evidence that the controller is:
  - efficient when it can be
  - stable when it must be
  - aggressive only when the path demands it

## Execution Plan

### Phase 1: Scenario Inventory
- Define deterministic scenario classes for:
  - clean
  - bursty
  - unstable
  - reordered
  - jitter-heavy
  - severe-loss

### Phase 2: Scenario Harness
- Reuse or extend existing FEC simulation and test harnesses.
- Capture:
  - effective redundancy
  - backend family reached
  - recovery ratio
  - transition count
  - latency / stall proxies
  - CPU proxy or benchmark time where available
- A dedicated targeted scenario suite now exists at `scripts/tests/suites/test-fec-auto-controller-scenarios.sh` and pins the current retained controller behavior for:
  - clean-link zero family
  - disturbance -> streaming
  - extreme loss -> fountain
  - cadence targeting
  - backend-family mapping
  - rank monotonicity
  - force-on promotion
  - no instant single-sample downshift
- A combined retained proof harness now also exists at `scripts/tests/suites/test-fec-auto-controller-proof.sh` and runs:
  - the targeted scenario suite
  - the retained FEC simulation bench suite
  - one top-level `results.json`
  - one top-level `summary.txt`

### Phase 3: Controller Tightening
- If scenarios expose:
  - nervous downshifts
  - delayed escalation
  - bad clean-link cost
  - over-eager fountain entry
  then tighten thresholds, hysteresis, or family transitions.

### Phase 4: Final Truth Sync
- Document the retained controller behavior and operational expectations.

## Acceptance Criteria
- [x] Clean-link zero-cost behavior is demonstrated in the targeted scenario suite.
- [x] Burst and unstable paths show stable escalation in the targeted scenario suite.
- [x] Extreme-loss behavior survives via retained heavy backends without pathological oscillation.
- [x] A first combined proof run exists and is green.
- [x] Docs explain the controller in measured rather than aspirational terms.

## Validation Status
- `bash -n scripts/tests/suites/test-fec-auto-controller-proof.sh`
- `bash scripts/tests/suites/test-fec-auto-controller-proof.sh --dry-run --fast`
- `bash scripts/tests/suites/test-fec-auto-controller-proof.sh --fast`
- First real proof run result:
  - `controller_scenarios`: green
  - `controller_bench`: green
  - artifacts: `scripts/out/tests/test-fec-auto-controller-proof-20260309_134208`
  - summary:
    - `ok=2`
    - `failed=0`
- Repeated proof run result:
  - `controller_scenarios_iter_1`: green
  - `controller_scenarios_iter_2`: green
  - `controller_bench_iter_1`: green
  - `controller_bench_iter_2`: green
  - artifacts: `scripts/out/tests/test-fec-auto-controller-proof-20260309_140830`
  - summary:
    - `ok=4`
    - `failed=0`
    - `scenario_ok=2`
    - `scenario_failed=0`
    - `bench_ok=2`
    - `bench_failed=0`

## Validation Matrix
- targeted FEC rust-tests
- FEC simulation / benchmark scripts
- combined proof harness
- `cargo check`
- `cargo clippy --all-targets --all-features -- -W clippy::all`

## Notes
- Public contract remains `off` / `auto`.
- This task is about proof and controller tightening, not expanding product surface.
- The repeated proof run gives the controller a broader evidence base than a single retained green pass.
