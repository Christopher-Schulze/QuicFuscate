---
id: TODO-1114
title: Negotiate WebTransport only with real transport and persona support
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1082, TODO-1096, TODO-1105]
---

# TODO-1114: WebTransport capability and persona coherence

## Why and evidence

The current WebTransport path is an H3 cover session, not the VPN/TUN
carrier (`src/transport/h3/connection/masque_and_webtransport.rs`).
`src/stealth/manager.rs::webtransport_cover_enabled` enables it for
StealthMax or the stealth dynamic image without checking the selected
browser persona or QUIC transport capabilities. H3 then sends
`SETTINGS_WT_ENABLED`, H3 DATAGRAM and related settings. The
`peer_supports_webtransport` predicate checks only received H3 settings,
not the peer's QUIC `max_datagram_frame_size` and `reset_stream_at` transport
parameters. The Chrome and Safari fixture entries explicitly mark
`reset_stream_at` absent. The Firefox fixture advertises the empty
`reset_stream_at` parameter, but the transport frame codec has no
`RESET_STREAM_AT` send/receive handler. Thus the local endpoint can claim a
capability it cannot fulfill, and a real draft-compliant peer can reject a
WebTransport session or send a frame the transport cannot process.
`is_webtransport_connect` also accepts any nonempty `:authority` and `:path`;
the server's H3 event handler then calls `accept_webtransport_cover_session`
and sends `200` without matching an authenticated service resource. A
private peer can therefore receive a fake successful cover session for a
host the listener does not serve. Bind acceptance to the authorized entry
resource and return a real refusal for unknown targets.
`open_webtransport_cover_session` always emits an `Origin` header formed from
the requested authority, but `is_webtransport_connect` and the acceptance
path never verify it. The July 2026 draft requires a browser client to send
Origin and requires the server to verify any supplied Origin before accepting
the session. An arbitrary Origin currently reaches the same generic `200`.

The current WebTransport-over-HTTP/3 draft snapshot, revision 16 dated
2026-07-06, requires H3 DATAGRAM, QUIC DATAGRAM and `reset_stream_at` on
both endpoints and permits the `webtransport-h3` CONNECT only after the
server advertises support:
https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16.
The related reliable-reset snapshot is revision 11 dated 2026-09-06:
https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11.
The pinned WebTransport setting codepoint `0x2c7cf000` matches revision 16.
These are versioned draft contracts, not RFCs or proof that public
browsers/edges interoperate with the current private service. Recheck the
latest revisions immediately before implementation or wire claims.

## Target contract

- One negotiated WebTransport capability is computed from the selected
  draft version, local transport implementation, local persona fixture,
  authenticated service binding, peer QUIC transport parameters and peer
  H3 SETTINGS. An H3 setting alone never promotes a missing QUIC extension
  into support. The default outer image does not advertise or attempt
  WebTransport when any mandatory capability is absent.
- If WebTransport cover is retained, implement the actual `RESET_STREAM_AT`
  frame and partial-delivery semantics in the existing transport frame,
  stream, recovery and flow-control owners before advertising the
  `reset_stream_at` parameter. Parse peer support and permit the extension
  only when both directions can honor it. Never add an inert frame handler
  solely to make a test green. Preserve current non-WebTransport stream
  behavior.
- The configured persona must reflect a real captured or documented H3/QUIC
  capability set. Do not inject a mandatory transport parameter into a
  browser fixture merely to enable cover; select a matching verified
  persona/service or leave WebTransport cover disabled. The negotiated H3
  SETTINGS, QUIC transport parameters, CONNECT request, and actual peer
  response form one consistent transcript.
- The server accepts a WebTransport CONNECT only for a configured resource
  on its authenticated authority. A syntactically valid request for an
  unrelated authority/path receives a bounded non-2xx response without
  creating a session or cover data stream. Never report a generic `200` as
  evidence that an arbitrary public host supports this private service.
- A browser-shaped request sends a real Origin matching its selected service
  context. The server validates any supplied Origin against the configured
  resource's allowlist and rejects a foreign or malformed Origin with a
  non-2xx response before session registration; absence follows the exact
  non-browser policy rather than a guessed browser default.
- Keep WebTransport as one bounded, genuine cover workload on the validated
  outer service, unless a measured carrier advantage justifies promoting it
  through TODO-1096's one inner-tunnel interface. Do not add a parallel VPN
  payload pipeline. Server push stays disabled under TODO-1110.

## Implementation and proof

- [ ] Pin the WebTransport H3 and reliable-reset draft revisions used for
      this wire format. Inventory every H3 setting, QUIC transport parameter,
      frame codepoint and session transition against the exact draft text;
      record the selected Chrome/Firefox/Safari fixture claims and actual
      authenticated edge support.
- [ ] Add a typed transport-capability projection from the existing QUIC
      negotiation state into H3. Gate local H3 settings and outgoing CONNECT
      on local implementation/persona support; gate incoming sessions and
      data streams on both peers' negotiated QUIC and H3 capabilities.
- [ ] Implement `RESET_STREAM_AT` completely in the current transport
      stream/recovery/flow-control path if the feature is enabled. Otherwise
      remove its fixture advertisement and disable WebTransport cover for
      that persona. Do not claim support based only on a copied fixture.
- [ ] Test missing/zero QUIC DATAGRAM, missing `reset_stream_at`, absent or
      malformed H3 settings, mismatched draft version, wrong CONNECT
      authority/path, absent/allowed/foreign/malformed Origin, valid
      session/open/data/close, and a peer-sent
      `RESET_STREAM_AT` with reliable-prefix, final-size and flow-control
      boundaries. Tests must exercise actual encoded QUIC/H3 packets and
      fail when a mandatory capability is removed.
- [ ] Capture the real outer handshake, H3 SETTINGS and WebTransport CONNECT
      against the selected authorized endpoint. Compare with the declared
      persona and verify that budget accounting and one-shot scheduling from
      TODO-1105 charge only emitted work. Update product documentation with
      the verified support boundary.

## Acceptance

- Zero `reset_stream_at` advertisements without a functioning receive path;
  zero WebTransport CONNECTs without all required local and peer QUIC/H3
  capabilities, an authorized service binding and a valid supplied Origin.
- The real peer accepts a complete session and data exchange for each
  enabled persona, or that persona's cover is disabled before its Initial.
  Capture proof identifies the draft revision and exact codepoints.
- Missing capability, unsupported frame, flow-control violation and failed
  endpoint authentication produce specified errors without fake success or
  parallel tunnel behavior.
