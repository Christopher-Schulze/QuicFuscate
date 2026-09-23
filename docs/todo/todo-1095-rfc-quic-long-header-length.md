---
id: TODO-1095
title: Restore mandatory RFC QUIC long-header Length framing
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-09-23
depends_on: []
---

# TODO-1095: RFC QUIC long-header Length framing

## Why and evidence

`src/transport/packet/headers.rs::format_header` writes version, connection
IDs and the Initial token, then returns the packet-number offset. The senders
in `src/transport/connection/send.rs` place the packet number immediately
there for Initial, Handshake and 0-RTT. `parse_header` mirrors that layout and
does not read the RFC Length varint. RFC 9000 sections 17.2.2 through 17.2.4
require Length before Packet Number for all three packet types. RFC 9369
changes QUIC v2 type bits and keys, not the presence of Length. The
`qf-aead-wire-proof` analyzer added in TODO-1029 treats the rest of a long
header datagram as the packet because the implementation has no Length. Its
private-AEAD result proves the two in-tree peers can exchange and decrypt
their private format; it cannot prove RFC QUIC framing, interoperability,
or browser-like wire appearance. An external parser should reject or
misparse this first flight; verify that with a captured packet before
claiming an observed outcome.

Primary specifications:
https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2,
https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.3,
https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.4,
https://www.rfc-editor.org/rfc/rfc9369.html.

## Target contract

- One RFC-compliant v1/v2 long-header encoder and parser. Initial, Handshake
  and 0-RTT carry a minimally encoded Length varint equal to packet-number
  bytes plus protected payload bytes including the AEAD tag. Retry and
  Version Negotiation retain their specified distinct layouts.
- The parser validates the declared packet span against the UDP datagram,
  rejects truncated/overflowing/forbidden shapes, and advances exactly to
  the next coalesced packet where permitted. It never treats trailing bytes
  as part of an authenticated packet merely because a local analyzer does.
- All send paths reserve Length field space before staging frames, encode
  the final value after payload sizing, and use the correct packet-number
  offset for header protection, associated data and sample placement.
  Maintain Initial minimum size, anti-amplification, PMTU, 0-RTT and Retry
  invariants. One canonical layout feeds production and wire proof; no
  permanent compatibility parser for the private format.
- Existing authenticated peers must migrate atomically. If wire compatibility
  is required during rollout, specify version negotiation and a bounded
  transition without silently accepting ambiguous packet boundaries.

## Implementation and proof

- [ ] Trace `format_header`, `parse_header`, all Initial/Handshake/0-RTT
      senders and receivers, packet-context views, GSO/coalescing, Retry,
      header protection, and `qf-aead-wire-proof` call signatures and tests.
- [ ] Encode/decode RFC v1 and v2 header vectors, Length boundaries at
      63/64 and 16383/16384, zero/maximum legal token lengths, truncated and
      oversized declared lengths, and mixed coalesced long/short packets.
- [ ] Apply the single corrected packet layout atomically across transport,
      analyzer, tests, and fixtures; remove assumptions that the long packet
      consumes the datagram. No new second wire-protocol implementation.
- [ ] Capture first flights at the receiving side after any GSO segmentation.
      Have an independent standards parser identify every packet boundary,
      version, type, Length and token; compare byte-for-byte with the local
      parser. Check a live peer handshake and QUIC v1/v2 negative cases.
- [ ] Re-run TODO-1029 private-AEAD boundary proof and TODO-1031 0-RTT
      evidence on the corrected format, plus TODO-1082/1085 persona gates.
      Update `docs/DOCUMENTATION.md`, `docs/MAP.md`, archived TODO-1029
      scope wording, and current product claims without rewriting the
      historical original result.

## Acceptance

- 100% of emitted Initial, Handshake and 0-RTT packets in captured supported
  runs have a valid RFC Length field and independent parser agreement on
  every packet boundary; zero accepted truncated or overlong spans.
- Authenticated v1/v2 handshakes, Retry, 0-RTT accept/reject, packet
  coalescing, and private post-auth 1-RTT pass their behavioral tests with
  no header-protection or AEAD associated-data mismatch.
- TODO-1029's private-cipher conclusion is re-established on the corrected
  wire format; all broader interoperability and persona claims remain gated
  until the independent capture evidence exists.
