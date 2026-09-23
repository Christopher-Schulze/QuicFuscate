---
id: TODO-1110
title: Return the RFC HTTP/3 error for an unauthorized push stream
severity: MED
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1055]
---

# TODO-1110: Unauthorized H3 push-stream error code

## Why and evidence

TODO-1055 removed synthetic server-push generation and the client's
`MAX_PUSH_ID` advertisement. In
`src/transport/h3/connection/receive.rs::classify_peer_unidirectional_stream`,
server-initiated stream type `0x01` returns `Error::StreamCreationError`.
A correctly client-initiated `0x01` already returns
`Error::StreamCreationError` on the server; the earlier audit claim that
it returned `Error::FrameUnexpected` was incorrect. Neither local result
queued an HTTP/3 application close frame. RFC 9114 Section 4.6 states that a client
receiving a push stream when it has not sent `MAX_PUSH_ID` must treat it as
`H3_ID_ERROR`; Section 6.2.2 requires `H3_STREAM_CREATION_ERROR` when a
server receives a client-initiated push stream. The code has `Error::IdError`
for this protocol condition elsewhere, including a `PUSH_PROMISE` without
a grant. The current test
`peer_push_streams_are_rejected` accepts the wrong stream error. Source:
https://www.rfc-editor.org/rfc/rfc9114.html#section-4.6.

## Target contract

- With no `MAX_PUSH_ID` grant, a correctly initiated server push stream
  produces `H3_ID_ERROR` at the connection boundary. A client-initiated
  push stream arriving at a server produces `H3_STREAM_CREATION_ERROR`
  under RFC 9114 Section 6.2.2. Classify the push stream type and endpoint
  role before returning either error; do not change unrelated wrong-initiator
  or unknown-stream behavior.
- Synthetic push generation, `MAX_PUSH_ID` advertisement and fake resource
  payloads remain disabled. Reintroduce push only under a separate measured
  genuine-resource design with client consent, cacheable/safe request
  semantics, validated origin authority and a demonstrable cover benefit.

## Implementation and proof

- [ ] Trace H3 `Error` to wire application-error mapping and the receive
      state machine for stream type `0x01`, `PUSH_PROMISE`, and wrong stream
      initiator; verify no later error replaces the chosen code.
- [ ] Return `Error::IdError` for a peer server push stream when no
      `MAX_PUSH_ID` was granted; preserve the server's existing
      `Error::StreamCreationError` classification. Queue the matching H3
      application close for both errors and retain all push-disabled settings.
- [ ] Update the existing real H3 connection tests to assert the emitted
      wire error code, not just a local enum: unauthorized server push,
      unauthorized `PUSH_PROMISE`, client-initiated push to server, and an
      unrelated unknown unidirectional type.
- [ ] Run focused H3 tests, the relevant transport suite and the existing
      HTTP/3 push-disabled guard; reconcile TODO-1055's outcome wording
      without rewriting its historical work log.

## Acceptance

- Unauthorized server push without `MAX_PUSH_ID` closes with `H3_ID_ERROR`;
  wrong-initiator push closes with `H3_STREAM_CREATION_ERROR`. Both are
  asserted from the real H3 connection's wire application error.
- No server-push cover sender, grant or fake resource path is restored.
