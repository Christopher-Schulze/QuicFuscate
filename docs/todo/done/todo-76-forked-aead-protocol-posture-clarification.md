# TODO 76: Forked AEAD Protocol Posture Clarification

## Scope
- `src/transport/packet.rs`
- `src/crypto.rs`
- docs/comments describing protocol posture

## Problem Statement (Audit Evidence, 2026-03-05)
- 1-RTT data-plane AEAD uses custom fork-only posture.
  - Evidence: `src/transport/packet.rs:1178`-`:1181`
  - Evidence: `src/crypto.rs:9320`, `:9359`, `:9455`
- That is valid only under the explicit full-fork assumption and should be treated/documented as such.

## Objectives
- Make custom AEAD protocol posture explicit and technically honest.

## Work Breakdown
- [x] Document fork-only AEAD posture clearly.
- [x] Align module comments/docs with the forked contract.
- [x] Review wording that could still imply upstream-normal QUIC expectations.

## Acceptance Criteria
- [x] Custom AEAD posture is explicit and not ambiguously framed as ordinary QUIC optimization.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Completed. Runtime-adjacent comments in `src/transport/packet.rs` and `src/crypto.rs` now state that the custom 0/1-RTT AEAD posture is valid only under the explicit full-fork assumption. `docs/DOCUMENTATION.md` carries the same boundary at the TLS/data-plane split, and `scripts/tests/audits/audit-runtime-guardrails.sh` enforces that wording.
