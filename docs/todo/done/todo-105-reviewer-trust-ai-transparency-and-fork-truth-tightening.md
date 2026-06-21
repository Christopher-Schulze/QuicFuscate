# TODO 105: Reviewer Trust, AI Transparency, and Fork Truth Tightening

## Scope
- AI-assisted development truth
- retained custom crypto truth
- fork transport divergence truth
- final reviewer-facing wording and guardrails

## Problem Statement
- The repository is much more honest than before, but a skeptical reviewer still needs one final clean explanation of:
  - what is custom
  - what is standard
  - what was intentionally removed
  - where the fork diverges from generic `quinn-udp` expectations
- Without one final tightening pass, the repo can still read as technically improved but narratively inconsistent.

## Desired End State
- A skeptical reviewer can quickly understand:
  - AI-assisted development was involved
  - the repo intentionally retains custom data-plane crypto
  - `MSG_ZEROCOPY` and busy-poll are not part of the final runtime story
  - transport overlap with `quinn-udp` is acknowledged honestly
  - the real proof surfaces are easy to find

## Current Truth Snapshot
- AI-assisted development transparency already exists.
- Security review fast-path and boundary maps already exist.
- `quinn-udp` overlap/divergence already has one canonical statement.
- The remaining work is final consolidation and anti-drift tightening.

## Architecture Gap
- Current truth is spread across multiple already-good documents.
- The final gap is consistency and emphasis, not missing content from scratch.

## Execution Plan

### Phase 1: Truth Inventory
- Re-audit README, canonical docs, review fast-path sections, and relevant module headers.
- Identify where wording still:
  - understates retained custom crypto
  - overstates standard-only posture
  - leaves removed Linux/socket micro-features implicit instead of explicit

### Phase 2: Consolidated Reviewer Story
- Tighten wording so the same truth appears everywhere:
  - AI-assisted development
  - retained custom data-plane crypto
  - `io_uring` canonical Linux path
  - no final retained `MSG_ZEROCOPY`
  - no final retained busy-poll
  - honest `quinn-udp` overlap/divergence

### Phase 3: Guardrail Sync
- Extend guardrails where needed so these truths cannot drift apart again.

## Acceptance Criteria
- [x] Canonical docs and reviewer fast-path docs tell one fully consistent story.
- [x] No stale wording suggests standard-only crypto or retained Linux/socket side stories that were intentionally removed.
- [x] Guardrails fail if the final reviewer-trust model drifts.

## Validation Matrix
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`
- docs consistency review
- `cargo check`

## Notes
- This is not marketing cleanup.
- It is the final defensibility pass for skeptical technical review.
