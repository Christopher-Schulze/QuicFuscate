---
id: TODO-1120
title: Bind QUIC handshake transport parameters to observed connection IDs and Retry
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1118]
---

# TODO-1120: QUIC handshake connection-ID transport-parameter binding

## Why and evidence

RFC 9000 Sections 7.3 and 18.2 require authenticated transport-parameter
checks against the connection IDs observed during the handshake. The
`qf-stealth` fixture encoder currently emits only local
`initial_source_connection_id` (0x0f); it has no runtime inputs or emitted
parameters for the server's `original_destination_connection_id` (0x00) and
`retry_source_connection_id` (0x10). The rustls provider builds the parameter
block from its local SCID alone. `Connection::poll_tls_and_validate_versions`
applies peer UDP limits and validates version information but does not bind
any peer CID parameters to the Initial/Retry packet history. TODO-1118 keeps
the original client DCID and accepted Retry SCID; neither is yet authenticated
by the server TLS transport parameters.

## Target contract

- The server's authenticated transport parameters contain its original
  destination CID for this connection, its own first Initial source CID, and
  the accepted Retry source CID exactly when the server sent Retry. The client
  sends its own first Initial source CID; server-only parameters are absent
  from client parameters. Values come from the actual packet/connection
  history, not persona fixtures or a configured cover origin.
- Each role validates mandatory, role-appropriate parameters once the peer
  TLS block becomes available. The client compares server original DCID with
  the original client Initial DCID, server initial SCID with the server's
  observed Initial SCID, and Retry SCID with the accepted Retry SCID (or
  requires absence without Retry). The server compares the client's initial
  SCID with the first accepted client Initial SCID. Missing, duplicate,
  malformed, role-forbidden, or mismatched CID parameters fail with QUIC
  TRANSPORT_PARAMETER_ERROR before handshake-ready/1-RTT delivery; malformed
  peer input never panics or overwrites the first error.
- The CID history is immutable after first authenticated observation and
  survives version negotiation and accepted Retry correctly. Server Retry
  token verification and server connection creation must provide the exact
  original DCID and Retry SCID without inferring them from the post-Retry
  Initial alone. If the current admission API lacks these inputs, extend its
  typed contract through the runtime caller rather than fabricating values.
- Persona ordering/GREASE remain cosmetic. Mandatory CID parameters cannot
  be omitted, fabricated, or reordered into a different meaning by persona
  selection or rustls provider rebuild. No parallel parameter encoder.

## Implementation and proof

- [ ] Trace the client/server Initial and Retry admission paths, token
      verification, `Connection` CID fields, rustls provider creation/profile
      rebuild, fixture encoder, and peer parameter parsing. Record exact
      ownership and event order for v1/v2, direct Initial and Retry.
- [ ] Define a typed handshake CID snapshot at the transport/TLS boundary.
      Pass actual role-specific values to the one existing parameter encoder;
      keep cosmetic fixture selection independent of mandatory values. Fail
      admission explicitly if a required server value is unavailable.
- [ ] Parse the authenticated peer parameter block with bounded QUIC varints,
      duplicate detection, role rules, CID length limits, and exact byte
      comparisons. Validate before exposing handshake completion or 1-RTT
      data and emit one transport close with code 0x08 on violation.
- [ ] Exercise paired rustls peers with v1/v2 direct Initial and real
      authenticated Retry. Inspect both emitted TLS parameter blocks and
      complete handshakes. Mutate each CID parameter separately to prove
      missing, duplicate, malformed, forbidden and wrong-value rejection;
      include profile rebuild and version negotiation paths.
- [ ] Run focused stealth, TLS, transport and core gates, Clippy/formatting;
      update `docs/DOCUMENTATION.md`, `docs/MAP.md`, and `docs/todo.md` with
      actual measured behavior. Keep independent standards-wire capture in
      TODO-1095.

## Acceptance

- Every successful paired v1/v2 direct or Retry handshake has exactly the
  role-correct CID parameters with byte-for-byte equality to captured packet
  history; all negative cases fail with peer-observable code 0x08 before
  application readiness.
- No synthetic or implicit connection ID is used to satisfy validation, and
  persona changes do not alter the mandatory CID set or values.
