---
id: TODO-1120
title: Bind QUIC handshake transport parameters to observed connection IDs and Retry
severity: HIGH
phase: S
priority: P1
status: DONE
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
by the server TLS transport parameters. The client receive path changes its
destination CID after a server Initial only while it still equals the original
client DCID. After Retry it instead equals the Retry SCID, so a distinct first
server Initial SCID is not adopted. Existing Retry packet-pump tests reuse the
Retry SCID as the server Initial SCID and do not exercise that transition.
RFC 9000 Section 7.2 explicitly permits the two changes. The live server's
validated Retry token already recovers the original DCID and binds the Retry
SCID to the next Initial DCID; the auth context does not carry the Retry event
or the first client Initial SCID onward as typed handshake identity.

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
  On the client, the first valid server Initial changes the destination CID
  from either the original DCID or the Retry SCID to that Initial's SCID; a
  later Initial with a different SCID is discarded before state mutation.
  Preserve presence separately from value, because an observed zero-length
  CID still requires a present, zero-length transport parameter.
- Persona ordering/GREASE remain cosmetic. Mandatory CID parameters cannot
  be omitted, fabricated, or reordered into a different meaning by persona
  selection or rustls provider rebuild. No parallel parameter encoder.

## Implementation and proof

- [x] Trace the client/server Initial and Retry admission paths, token
      verification, `Connection` CID fields, rustls provider creation/profile
      rebuild, fixture encoder, and peer parameter parsing. Record exact
      ownership and event order for v1/v2, direct Initial and Retry.
- [x] Define a typed handshake CID snapshot at the transport/TLS boundary.
      Pass actual role-specific values to the one existing parameter encoder;
      keep cosmetic fixture selection independent of mandatory values. Fail
      admission explicitly if a required server value is unavailable.
- [x] Parse the authenticated peer parameter block with bounded QUIC varints,
      duplicate detection, role rules, CID length limits, and exact byte
      comparisons. Validate before exposing handshake completion or 1-RTT
      data and emit one transport close with code 0x08 on violation.
- [x] Exercise paired rustls peers with v1/v2 direct Initial and real
      authenticated Retry. Inspect both emitted TLS parameter blocks and
      complete handshakes. Mutate each CID parameter separately to prove
      missing, duplicate, malformed, forbidden and wrong-value rejection;
      include profile rebuild and version negotiation paths.
- [x] Run focused stealth, TLS, transport and core gates, Clippy/formatting;
      update `docs/DOCUMENTATION.md`, `docs/MAP.md`, and `docs/todo.md` with
      actual measured behavior. Keep independent standards-wire capture in
      TODO-1095.

## Acceptance

- Every successful paired v1/v2 direct or Retry handshake has exactly the
  role-correct CID parameters with byte-for-byte equality to captured packet
  history. Every negative parser case queues exactly one transport close with
  code `0x08`; genuine v1/v2 rustls peers prove that the same rejection path
  reaches the peer from either role before application readiness.
- No synthetic or implicit connection ID is used to satisfy validation, and
  persona changes do not alter the mandatory CID set or values.

## Current trace

- `RetryTokenManager::validate` checks the token's Retry SCID against the
  retried Initial DCID and returns the original DCID. `LiveInitialAuthContext`
  carries the original and current key DCIDs to server connection creation,
  but drops the explicit validated-Retry provenance and first client SCID.
- `QuicFuscateConnection::new` constructs the rustls provider before the
  server processes its first client Initial; local server SCID, original DCID,
  and validated Retry SCID must therefore be available before that call.
- `Connection::recv` observes the first decrypted peer Initial later; this
  is the right owner for the peer initial SCID and the client destination-CID
  transition. The former `dcid == initial_dcid` condition failed after Retry.
- `qf-stealth::encode_transport_params` and the rustls provider rebuild use
  only local SCID plus version information. Handshake polling applies UDP
  limits and validates version information, with no CID identity check.

## Verification record

- A real v1/v2 Retry packet pump with distinct Retry and server Initial SCIDs
  failed on the retained Retry SCID. The client now records the first
  authenticated peer Initial SCID separately from Retry, adopts it as the
  destination CID, and discards later Initials whose SCID differs before
  packet-number or connection state mutation. The targeted distinct-SCID
  handshake and paired conflicting-Initial test pass. Authenticated TLS
  transport-parameter emission/validation and the full gate remain open.
- The single persona encoder now accepts a role-typed CID snapshot, preserving
  fixture order for the initial SCID and adding server original/Retry CIDs.
  The live admission context records Retry provenance from a validated token
  and passes it to the server connection before TLS provider construction.
- Production server construction rejects missing Initial-key DCID and
  inconsistent Retry inputs; `enable_tls` rejects a missing server original
  DCID. The benchmark-only synthetic pair now carries explicit, consistent
  Initial CID history so its core wrapper still enables real TLS.
- Paired v1/v2 direct, accepted-Retry with distinct Retry/Initial SCIDs, and
  v2-to-v1 VN handshakes complete with exactly the emitted role-specific CID
  fields. A real rustls wrong-CID transcript closes on each role with a
  peer-received transport error `0x08` in v1 and v2. Parser tests cover
  missing/duplicate/truncated/oversized/wrong/forbidden fields, Retry
  presence and mismatch, and present zero-length values. Transport tests
  passed 160/160, core tests 77/77 plus a focused constructor-contract test,
  root qftls tests 33 passed and one environment-specific ignored plus a
  focused role/length guard test, and qf-stealth transport-parameter tests
  passed 6/6. Both root library and qf-stealth strict Clippy pass; formatting
  and diff checks pass. A final v1/v2 direct/Retry/wrong-CID packet pump passed
  3/3 after the constructor guard was added.
- TODO-1121 separately owns core's pre-existing warning-only TLS setup errors
  and provider-less readiness; this task does not claim that construction
  failure boundary is fixed.

## Evidence boundary

Malformed, duplicate, forbidden, missing, oversized and Retry-presence inputs
are checked directly at the one transport-parameter validator and each queues
`0x08`. Real rustls packet pumps inject wrong authenticated CID values on
both roles under v1 and v2 and verify the remote endpoint receives `0x08`.
The shared close path is exercised without adding a test-only malformed-TLS
parameter override to the production provider API. Independent standards-wire
capture and packet-format conformance remain TODO-1095.
