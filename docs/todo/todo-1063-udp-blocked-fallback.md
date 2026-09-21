---
id: TODO-1063
title: When UDP is blocked, fall back to MASQUE or real TLS
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1048]
---

# TODO-1063: When UDP is blocked, fall back to MASQUE or real TLS

## Why

A QUIC VPN on its own UDP port is dropped by filters that allow only known HTTP/3 destinations. XTLS Vision does not port: it splices inner TLS onto TCP to hide a second record layer. QUIC already has one encryption layer, the packet. A second TLS record layer on UDP would be a parrot (TODO-1062). The equivalent of "look like ordinary HTTPS" is an outer hop that already is HTTP/3 or TLS to a real destination.

## Current code

- MASQUE relay exists (`src/implementations/server/masque_relay.rs`, H3 datagrams).
- The default client dial is QUIC over UDP to the configured server.
- Reality relay is the probe fallback (TODO-1048), not a UDP-block fallback.
- There is no TCP TLS tunnel fallback.

## Target

- If the UDP dial fails with timeout or unreachable, and an outer hop is configured, the client retries once:
  - MASQUE to an HTTP/3 endpoint, or
  - a real TCP TLS connection to that class of endpoint, carrying the tunnel inside HTTP, not inside a custom record layer.
- The outer handshake is rustls with the TODO-1047 persona. SNI matches the certificate (TODO-1048).
- Inner QUIC is the MASQUE payload, not its own UDP 5-tuple toward the censor.
- This fallback is for `stealth`, `Stealth MAX`, and `dynamic`. `off` and `performance` stay on direct UDP.
- Do not implement Vision or a fake TLS stack.

## Non-goals

- No CDN account automation.
- No frontend visual change.
- A dedicated IP is not hidden. The config comment says the hop only helps when its IP is shared with real sites.

## Design

1. `OuterHop::{None, Masque, TlsHttp}` on the client config. Default `None`. Do not silently pick a public site.
2. When `OuterHop` is set: try UDP, on hard failure try the outer hop once. Do not flap per packet.
3. MASQUE reuses the existing relay. The TLS HTTP path uses rustls and an in-tree HTTP client if one exists. If no HTTP client exists, stop at MASQUE and record TLS CONNECT as a follow-up in this file. Do not invent a parser.
4. Tests use a local listener. No public network.

## Sub-Tasks

- [ ] Config enum and dial order.
- [ ] Timeout and unreachable trigger fallback. A TLS alert does not.
- [ ] Local MASQUE test: UDP listener down, application bytes still flow.
- [ ] Config comment: a dedicated IP is not hidden.

## Acceptance

- `OuterHop::None` keeps today's dial.
- A blackholed UDP server plus a local MASQUE hop still carries application bytes.
- No Vision splice code.

## Risks

- Flapping between UDP and MASQUE creates two fingerprints. One failure, one fallback, then stick for the connection.
