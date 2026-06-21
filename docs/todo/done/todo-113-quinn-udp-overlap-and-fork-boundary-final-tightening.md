# TODO 113: Quinn-UDP Overlap and Fork Boundary Final Tightening

## Scope
- transport overlap truth
- fork divergence truth
- reviewer-facing transport explanation

## Problem Statement
- The current docs already explain overlap versus divergence better than before.
- The remaining opportunity is to make that explanation shorter, sharper, and harder to misread.

## Desired End State
- A reviewer can immediately see:
  - what overlap is normal
  - what divergence is intentional
  - why the repo is not reducible to `quinn-udp`

## Current Truth Snapshot
- A transport overlap/divergence section already exists.

## Architecture Gap
- The current explanation is accurate.
- It can still become more direct and more reusable across review-facing surfaces.

## Execution Plan

### Phase 1: Overlap Matrix Tightening
- Reduce the explanation to the minimum high-signal set of overlap categories and divergence points.

### Phase 2: Consistency Pass
- Ensure README and canonical docs tell the same short transport truth.

## Acceptance Criteria
- [x] Transport overlap versus divergence is harder to misread.
- [x] README and canonical docs tell the same concise story.

## Validation Matrix
- documentation review
- runtime guardrails if wording is guarded

## Final Status
- Completed.
- README and canonical docs now tell the same shorter transport truth:
  - generic UDP capability overlap with `quinn-udp` is real
  - fork-specific divergence begins where transport crosses into:
    - data-plane packet protection
    - FEC/adaptive policy coupling
    - stealth/timing/runtime shaping
    - integrated server/control-plane ownership
- The wording remains guardrail-protected.
