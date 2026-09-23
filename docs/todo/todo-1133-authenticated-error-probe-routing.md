---
id: TODO-1133
title: Keep authenticated QUIC failures out of Reality probe fallback
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1132]
---

# TODO-1133: Classify transport failures before stealth fallback

## Why and evidence

`src/core/connection.rs::deliver_wire_payload` forwards every non-TLS
`Connection::recv` error to `StealthManager::handle_fallback`, which can send
cached cover TLS material or invoke the Reality proxy. An authenticated QUIC
packet with a CRYPTO capacity, frame or protocol violation can already have
caused a local transport close. Routing that packet as an unauthenticated
probe mixes a real connection error with the probe persona and can produce
an unrelated cover response while a QUIC close is queued. This is directly
reachable after TODO-1132; the general packet-admission classification is
also tracked by TODO-1129.

## Target contract

- Forward only packets classified as unauthenticated or explicitly
  discardable probes to the Reality fallback. A transport error after
  authenticated packet processing or a local close does not emit cached
  cover material or relay traffic.
- Preserve the protected QUIC close send opportunity and original typed
  terminal cause. Avoid turning every malformed unauthenticated datagram
  into a connection teardown, which would weaken active-probe resistance.
- Use the smallest reliable classification boundary backed by the transport
  receive result and close state. If close state alone cannot distinguish all
  live authenticated errors, add one typed receive disposition at the owner;
  do not infer authentication from error enum names or duplicate packet
  parsing in Core.

## Implementation and proof

- [ ] Trace Core raw/FEC receive callers, Reality cached/relay effects and
      transport error/close ownership; identify which errors are pre- and
      post-authentication.
- [ ] Apply one classification and routing rule across raw, recovered and
      batched receive paths without adding a second stealth policy engine.
- [ ] Add real-code tests for an unauthenticated probe, a decrypted invalid
      CRYPTO packet, a TLS terminal failure and an accepted packet; assert
      exact fallback/close/peer behavior and no double response.
- [ ] Run relevant transport/Core/stealth tests, default and feature library
      gates, strict Clippy and formatting; document native wire limits.

## Acceptance

- Authenticated terminal failures never enter Reality fallback; probe
  traffic still receives only the configured cover behavior.
- The peer can receive the one correct protected QUIC close, and all
  required gates pass.
