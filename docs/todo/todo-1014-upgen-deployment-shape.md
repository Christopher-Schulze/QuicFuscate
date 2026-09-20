---
id: TODO-1014
title: UPGen-style deployment-seeded private-protocol wire-image diversity
severity: MEDIUM
phase: L
priority: P2
status: OPEN
created: 2026-09-20
depends_on: []
---

# TODO-1014: Deployment-seeded wire-image diversity (UPGen adaptation)

## Objective
Every QuicFuscate deployment currently emits the same private-capsule wire
shape: `QFPA` magic, capsule type 0x41, fixed Proposal/Selection/
Confirmation layout, fixed AEAD-family preference ordering, fixed
exporter salts. Content entropy is per-connection (HKDF from the
authenticated transcript), but *shape* is deployment-invariant - a censor
with one deployment's capture can signature-match all deployments. UPGen
(2025) formalizes the fix: per-deployment protocol variants that classify
as "unknown benign encrypted" rather than a known circumvention protocol.

Design study recorded in
`docs/todo/todo-1010-stealth-shaping-research-track.md` (candidate 5).

## Implementation plan

1. `PrivateProtocolShape` descriptor in `src/qftls/private_protocol.rs`:
   a 32-byte `deployment_seed` expands via HKDF (new exporter label) into
   shape knobs:
   - TLV field emission order inside the Proposal capsule
   - pad-to granule for control capsules (e.g. 0/16/32-byte alignment)
   - AEAD-family preference list ordering in the Proposal
   - negotiation pacing pattern (inter-capsule delay hints)
   Wire *semantics* stay fixed; only wire *layout* permutes.
2. Seed provisioning: the seed travels with the provisioned credential
   material (QKey registry entry / server config `[stealth]` section +
   client profile), never negotiated on the wire - negotiating it would
   reintroduce a fixed signature. Absent seed = today's canonical shape
   (backward compatible).
3. Encoder/decoder plumbing: the Proposal encoder walks the permuted TLV
   order; the decoder already tolerates unknown/duplicate fields (verify -
   if not, make it order-agnostic, which is the correct posture anyway).
4. Tests: two different seeds produce byte-different Proposal capsules
   that still round-trip; absent seed keeps the canonical layout;
   mismatched seeds are detected via the existing transcript hash
   (confirmation fails closed).

## Risks
- Decoder must be order-agnostic before the encoder permutes - ship both
  in one commit so mismatched deployments degrade to auth-failure, never
  to a parse divergence.
- Seed reuse across deployments silently re-collapses diversity; document
  that the seed must be per-installation, not per-release.

## Acceptance
- `PrivateProtocolShape` derives all four knob sets from one seed; unit
  tests prove seed A != seed B layouts and round-trip correctness.
- No wire change for deployments without a configured seed.
- `docs/DOCUMENTATION.md` documents the seed provisioning path.
