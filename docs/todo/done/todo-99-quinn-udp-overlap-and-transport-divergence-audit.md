# TODO 99: Quinn-UDP Overlap and Transport Divergence Audit

## Scope
- transport conceptual overlap review
- fork-specific divergence statement
- reviewer-facing transport rationale

## Problem Statement
- A fair external criticism is that parts of the transport layer may look like they overlap heavily with `quinn-udp`.
- The right response is a precise divergence audit, not vague novelty claims.

## Desired End State
- A technically grounded statement of:
  - where the conceptual overlap exists
  - what the fork-specific retained transport behavior is
  - why QuicFuscate still owns its own transport machinery

## Execution Plan

### Phase 1: Overlap Inventory
- Identify the transport areas that are generic QUIC-ish machinery versus fork-specific retained behavior.
- Completed against the current public `quinn_udp` docs surface as of 2026-03-09:
  - `UdpSocketState`
  - `Transmit`
  - `RecvMeta`
  - GSO/GRO
  - ECN
  - buffer sizing / fragmentation controls

### Phase 2: Divergence Statement
- Document fork-specific retained transport decisions without exaggerating novelty.
- Implemented in canonical docs as:
  - `docs/DOCUMENTATION.md` -> `Transport Overlap and Divergence vs quinn-udp`

### Phase 3: Reviewer-Facing Sync
- Tighten docs and review-readiness materials so this question can be answered directly.
- Implemented in:
  - `README.md` -> `Security Review Fast Path`
  - `scripts/tests/audits/audit-runtime-guardrails.sh` drift check for the overlap/divergence statement

## Acceptance Criteria
- [x] The repo has a technically defensible overlap/divergence statement.
- [x] Reviewer-facing docs stop relying on implicit novelty claims.

## Validation Status
- `bash -n scripts/tests/audits/audit-runtime-guardrails.sh`
- `bash scripts/tests/audits/audit-runtime-guardrails.sh`
- Result:
  - `Critical: 0`
  - `Warnings: 0`

## Validation Matrix
- docs consistency
- runtime truth alignment with current transport code

## Notes
- This is an honesty and defensibility task, not an upstreaming promise.
