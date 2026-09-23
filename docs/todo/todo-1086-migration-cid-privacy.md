---
id: TODO-1086
title: Rotate the QUIC connection ID with deliberate disguise migration
severity: MED
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1056, TODO-1116]
---

# TODO-1086: Migration CID privacy

## Why and evidence

TODO-1056's target calls for connection-ID and port rotation, but its DONE
record says the DCID remains stable. A new source port with the same visible
DCID can be linked to the old path, so the current behavior is a NAT-rebind
signature, not a convincing privacy rotation. RFC 9000 section 9 describes
new connection IDs and path validation for migration and warns that zero-CID
paths are trivially linkable:
https://www.rfc-editor.org/rfc/rfc9000.html.
TODO-1116 owns a more basic failure in the current two-socket migration path:
the old socket is not polled, new-socket receives use the old local address,
and the connected send helper discards transport path metadata. Repair and
prove that routing before claiming a CID/privacy improvement.

## Target contract

- Deliberate, stealth-mode disguise migration after handshake confirmation
  changes the source UDP port and adopts an unused, peer-issued destination
  CID. Validate the new path with the existing PATH_CHALLENGE/RESPONSE flow;
  preserve packet number and crypto state and do not send a new Initial.
- Honor `disable_active_migration`, zero-length CID, active CID limit,
  sequence/retire-prior-to, stateless reset tokens, and spare-CID exhaustion.
  If a fresh CID is unavailable or the peer prohibits migration, skip the
  deliberate disguise attempt and report why. Do not promise unlinkability
  on a stable CID. Passive NAT rebinding remains independently supported.
- Retire the old peer CID only after new-path validation and safe standby
  transition. Roll back port/path and CID coherently on failure; never reuse
  a retired CID. Capture-derived persona cadence remains the gate for any
  periodic schedule rather than assuming a 120-600 s timer is browser-like.

## Implementation and proof

- [ ] Map CID issuance/storage/selection/retirement in transport and server
      routing before edits; verify exact method signatures and invariants.
- [ ] Add bounded peer-CID inventory and atomic path/CID transition without
      changing unrelated handshake or loss recovery behavior.
- [ ] Test new CID, zero-length CID, no spare, disabled migration, path
      validation success/failure, stateless reset token handling, and NAT
      rebinding separately.
- [ ] Capture both sides before/after and prove old/new 4-tuple and DCID,
      absence of new Initial/TLS handshake, and successful bidirectional app
      traffic. Reconcile TODO-1056's target and outcome wording.

## Acceptance

- 100% of successful deliberate disguise migrations use a new valid peer
  DCID and source port; 0 such attempts run where the peer forbids them or
  provides no spare CID. Failed validation restores the prior usable path.
- Packet capture proves continuity without a new handshake and shows no
  plaintext/application loss during the transition. Claims of browser-like
  cadence require a corresponding captured browser trace.
