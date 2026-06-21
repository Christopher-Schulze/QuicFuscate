# TODO 115: FEC Auto-Controller Empirical Proof Expansion

## Scope
- retained FEC sophistication evidence
- clean-link efficiency proof
- escalation proof under hard loss
- controller transition stability evidence

## Problem Statement
- The FEC architecture is now much cleaner and product-facing `Auto` / `Off` is correct.
- The remaining reviewer question is:
  - does the retained internal sophistication earn its keep under real scenarios?

## Desired End State
- The repo can prove:
  - near-zero cost when the path is clean
  - stable escalation when the path degrades
  - aggressive protection when necessary
  - controlled recovery when conditions improve

## Current Truth Snapshot
- FEC scenario and proof suites already exist and are meaningful.

## Architecture Gap
- The current proof is good engineering evidence.
- It can become stronger empirical evidence with clearer cost/stability summaries and longer scenario coverage.

## Execution Plan

### Phase 1: Scenario Expansion
- Extend clean-link, burst-loss, high-jitter, reorder, and sustained-bad-path scenarios.

### Phase 2: Efficiency Evidence
- Add clearer summaries for:
  - zero/near-zero overhead behavior on clean links
  - cadence changes
  - family escalation
  - controller downshift stability

### Phase 3: Proof Output Tightening
- Ensure scenario runs produce compact evidence artifacts that are reviewer-usable.

## Acceptance Criteria
- [x] FEC `Auto` efficiency on clean links is clearly demonstrated.
- [x] Escalation and recovery behavior is clearly demonstrated.
- [x] Proof outputs are concise and reviewer-usable.

## Validation Matrix
- FEC proof scripts
- scenario suite
- docs sync
