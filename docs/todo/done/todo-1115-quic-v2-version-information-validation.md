---
id: TODO-1115
title: Require authenticated QUIC v2 version information on both endpoints
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: []
---

# TODO-1115: QUIC v2 version-information validation

## Why and evidence

`src/transport/connection/lifecycle/tls_and_crypto.rs::validate_peer_version_information`
sets `required = !self.is_server && (v2 || reacted_to_vn)`. On a v2 server,
an authenticated empty peer transport-parameter block therefore sets
`peer_information_validated = true` and returns success. The test
`server_may_accept_missing_version_information_and_client_accepts_retiring_choice`
in `src/transport/connection/tests.rs` requires this exception. The server
also calls `maybe_queue_handshake_done` after the validation call. RFC 9369
Section 4 says any endpoint supporting QUIC v2 MUST send, process and
validate the `version_information` transport parameter to prevent downgrade.
The current v2 server acceptance violates that contract. This is source
proof; no external v2 peer capture has yet been checked. RFC source:
https://www.rfc-editor.org/rfc/rfc9369.html#section-4.

## Completed implementation and proof (2026-09-23)

The both-role v2 requirement, authenticated-completion gate and server
`HANDSHAKE_DONE` gate are patched locally. The old permissive server test is
replaced by an error-code assertion; both-role malformed, duplicate and
wrong-choice cases, both-role real-TLS missing-parameter rejection, and
in-memory v1/v2, VN-to-v1 with a legacy v1 server, and v2-Retry rustls handshakes are added. The real
Retry test exposed a missing Initial CRYPTO requeue after
the client adopts the Retry token and CID; the receive path now requeues the
retained rustls Initial flight under the freshly derived keys. These changes
also exposed that a failed version check could repeatedly block its queued
CONNECTION_CLOSE. The send path now emits the close in the peer-readable
Initial or Handshake space before re-polling the rejected parameter; the real
negative test checks the peer-received error code. `cargo test --offline --lib
transport::connection:: -- --quiet` passed 157/157; `core::connection::tests::`
passed 77/77; `qf-transport-version` passed 7/7; `cargo clippy --offline
--lib -- -D warnings` and `cargo fmt --all -- --check` passed. RFC 9368 Sections 3 and 8 permit
missing information on v1 as a legacy compatibility case, including the
synthetic v1-only server list after a client reacts to VN. No v2 connection
inherits that exception. Wire interoperability remains unclaimed pending
TODO-1095's standards framing and independent packet capture.

## Target contract

- For a connection negotiated as v2, both client and server require one
  correctly framed and authenticated `version_information` parameter before
  treating peer version information as validated or queueing server
  `HANDSHAKE_DONE`. Absence, duplicates, malformed lengths, chosen-version
  mismatch or a downgrade-inconsistent available list close with the
  specified transport-parameter or version-negotiation error.
- Preserve v1 compatibility only where the relevant version-negotiation
  specification permits a v1-only peer to omit the parameter. Document the
  exact condition; do not apply the exception to a v2 connection or use
  `is_server` alone as an exemption.
- Keep the existing `qf-transport-version` parser/encoder as the single
  owner. Validate only after rustls authenticates the peer transport
  parameters, and do not mark the state complete while parameters are absent
  during an in-progress handshake. Any re-handshake/version switch resets
  the validation state before use.
- Fix the test that currently asserts v2 server acceptance. Verify local
  v1/v2 handshakes, Version Negotiation, Retry, and a v1-only legacy peer
  against RFC 9369 and the negotiated-version binding. The parser and
  in-memory TLS tests can land independently; coordinate the final
  standards-wire capture with TODO-1095.

## Implementation and proof

- [x] Trace `enable_tls`, `poll_tls_and_validate_versions`,
      `validate_peer_version_information`, `maybe_queue_handshake_done`,
      `qf_transport_version::find_version_information`, version-switch reset,
      and both role tests to an authenticated peer-parameter boundary.
- [x] Replace the role-only missing-parameter exemption with an explicit
      negotiated-version rule. Keep error codes and reason strings stable
      where correct; define the exact v1-only compatibility exception.
- [x] Test v2 client and server with valid, missing, duplicated, malformed,
      wrong-chosen, downgrade-inconsistent and peer-unavailable parameters.
      Assert no server `HANDSHAKE_DONE` before successful validation.
- [x] Test v1/v2 negotiation, v1 legacy compatibility and Retry with real
      in-memory TLS peers; update `docs/DOCUMENTATION.md`, `docs/MAP.md` and
      the version-negotiation task history. Independent first-flight wire
      parsing remains in TODO-1095; no external interoperability is claimed.

## Acceptance

- Zero v2 handshakes complete on either role without one authenticated,
  valid `version_information` parameter. The current permissive server test
  is replaced by a failing negative case, not disabled or weakened.
- A legitimate v1-only peer remains compatible only under the documented
  exception; malformed and downgrade attempts fail with precise errors.
  Both roles pass the local handshake and version-negotiation matrix.
