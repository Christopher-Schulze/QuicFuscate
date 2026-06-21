# TODO 97: Security/Crypto Review Readiness Pack

## Scope
- review-oriented summaries
- security boundary mapping
- reviewer-facing invariant references

## Problem Statement
- Even with cleaner code, an external or semi-external reviewer still needs a fast route to the real proof surfaces.
- The repository needs a deliberate review-ready pack for the most sensitive boundaries.

## Desired End State
- A skeptical reviewer can quickly find:
  - packet protection ownership
  - TLS boundary ownership
  - data-plane AEAD posture
  - retained unsafe/SIMD machine room
  - relevant tests and guards

## Execution Plan

### Phase 1: Sensitive Boundary Index
- Build a compact review-oriented index of the sensitive modules and their exact owner claims.
- Implemented in canonical docs as `Security Review Boundary Map` with:
  - boundary
  - canonical owner
  - retained constraint
  - strongest proof surfaces

### Phase 2: Invariant Summaries
- Add short, precise review-facing summaries for:
  - data-plane AEAD
  - TLS boundary
  - packet protection
  - unsafe SIMD boundaries
- Implemented as:
  - boundary rows in `docs/DOCUMENTATION.md`
  - `Reviewer Checklist`
  - `Security Review Fast Path` pointer section in `README.md`

### Phase 3: Proof Surface Linking
- Link each review summary to its strongest local proof surfaces:
  - tests
  - audits
  - key docs
- Guardrail added:
  - `scripts/tests/audits/audit-runtime-guardrails.sh` now fails closed if the explicit review map disappears from canonical docs.

## Acceptance Criteria
- [x] Review-ready index exists for the sensitive boundaries.
- [x] The proof surfaces are easy to find.
- [x] The repo is easier to hand to a skeptical reviewer without extra verbal explanation.

## Validation Status
- `bash -n scripts/tests/audits/audit-runtime-guardrails.sh`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`
- Result:
  - `Critical: 0`
  - `Warnings: 0`

## Validation Matrix
- docs consistency checks
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`

## Notes
- This is a review-readiness pack, not a marketing document.
