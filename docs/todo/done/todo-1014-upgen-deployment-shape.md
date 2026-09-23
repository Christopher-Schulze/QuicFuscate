---
id: TODO-1014
title: UPGen-style deployment-seeded private-protocol wire-image diversity
severity: MEDIUM
phase: L
priority: P2
status: DONE
created: 2026-09-20
depends_on: []
---

# TODO-1014: Deployment-seeded wire-image diversity (UPGen adaptation)

## Objective
Every QuicFuscate deployment previously emitted the same private-capsule
wire shape: `QFPA` magic, capsule type 0x41, fixed Proposal/Selection/
Confirmation layout, fixed AEAD-family preference ordering, fixed
exporter salts. Content entropy is per-connection (HKDF from the
authenticated transcript), but *shape* was deployment-invariant - a
censor with one deployment's capture could signature-match all
deployments. UPGen (2025) formalizes the fix: per-deployment protocol
variants that classify as "unknown benign encrypted" rather than a known
circumvention protocol.

Design study recorded in
`docs/todo/done/todo-1010-stealth-shaping-research-track.md` (candidate 5).

## Implemented design (adapted)

Code inspection showed the wire format is a **strict fixed-layout binary
message**, not TLV - the decoder reads fields in one order and rejects
trailing bytes. The original TLV-permutation plan was therefore replaced
with a versioned layout permutation:

- `PrivateProtocolShape` (`src/qftls/private_protocol.rs`) expands a
  32-byte `deployment_seed` via domain-separated HKDF
  (`qf private protocol shape v1`) into:
  - a Fisher-Yates permutation of eight wire blocks: local nonce,
    peer nonce, QKey transcript hash, context hash, ALPN, original DCID,
    current DCID, and a pad block (~161k distinct layouts),
  - a pad granule of 0/16/32/64 bytes with deterministic seed-derived
    pad content,
  - an inter-capsule pacing hint (`pacing_hint_us`, timing knob only -
    no wire parse effect).
- Wire versioning: canonical deployments keep emitting version 1
  byte-identically; a non-canonical shape emits
  `PRIVATE_PACKET_PROTECTION_VERSION_SHAPED` (2). The version byte keeps
  its fixed position so the decoder selects the layout before parsing.
- The fixed scalar header (magic, version, kind, generation, family
  mask, role, flags, AEAD profile, epoch, write boundary, QUIC version,
  length prefixes) never moves. The v1 reserved byte carries `pad_len`
  in v2. The authenticator always closes the message and binds the exact
  encoded byte image - a seed mismatch lands fields in different
  positions and fails closed at authentication (or earlier at the
  version/length gates).
- Seed provisioning: `[crypto] private_shape_seed` (hex, 64 chars) in the
  engine config travels with the deployment's credential material. It is
  never negotiated on the wire. Absent seed = canonical shape, fully
  backward compatible. The seed must be **per-installation**, not
  per-release - reuse silently re-collapses diversity.
- Plumbing: `CryptoConfig::private_shape_seed_bytes()` decodes the seed;
  `QuicFuscateConnection::set_private_protocol_shape` installs it;
  `PrivateNegotiationMachine::with_shape` binds it before any message is
  built or received. Client, circuit-hop, and server live-state paths
  all plumb it through.

## Tests
- `distinct_seeds_produce_distinct_shapes`
- `seeded_shape_emits_shaped_version_and_round_trips` (v2 wire byte,
  round-trip equality, authenticator verifies)
- `absent_seed_keeps_canonical_v1_wire_image` (v1 byte, reserved=0,
  canonical encode byte-identical)
- `mismatched_seed_fails_closed` (wrong-seed decode fails or
  authenticator rejects; canonical decoder rejects v2 outright)
- `seeded_full_negotiation_reaches_switch_scheduled` (full
  Proposal/Selection/Confirmation under a seeded shape)
- `shaped_layout_binds_pad_block_and_order_to_authenticator`

## Acceptance
- `PrivateProtocolShape` derives all knob sets from one seed; unit tests
  prove seed A != seed B layouts and round-trip correctness. DONE
- No wire change for deployments without a configured seed. DONE
- `docs/DOCUMENTATION.md` documents the seed provisioning path. DONE
