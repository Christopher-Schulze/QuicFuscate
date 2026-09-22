---
id: TODO-1063
title: When UDP is blocked, fall back to MASQUE or real TLS
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-21
completed: 2026-09-22
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

- [x] Config enum and dial order.
- [x] Timeout and unreachable trigger fallback. A TLS alert does not.
- [x] Local MASQUE test: UDP listener down, application bytes still flow.
- [x] Config comment: a dedicated IP is not hidden.

## Acceptance

- `OuterHop::None` keeps today's dial.
- A blackholed UDP server plus a local MASQUE hop still carries application bytes.
- No Vision splice code.

## Implementation notes

- `OuterHop::{None, Masque, TlsHttp}` lives next to `StealthMode` in
  `qf-engine-types` (`connection.outer_hop`, `connection.outer_hop_relay`).
  `TlsHttp` is deliberately rejected at validation: there is no in-tree HTTP
  CONNECT client, so the spec's "real TCP TLS" path stops at MASQUE rather than
  growing a fake record layer. Recorded here as the follow-up.
- `Engine::connect` synthesizes the fallback plan *before* the direct dial
  (`outer_hop_fallback_config` in `config_projection.rs`): the configured relay
  becomes hop 0 (`role = "relay"`), `legacy_circuit_config` turns the legacy
  endpoint/SNI/QKey fields into the exit hop, and the consumed legacy keys are
  neutralized so the canonical "circuit XOR legacy" rule still validates.
- Eligibility is classified by `dial_failure_is_reachability`:
  `DataPlaneFault::TransportReceive` with a `UDP receive` component (ICMP
  unreachable) or a `Connection` timeout. TLS alerts, control-plane rejects,
  and client-closed paths do not match, so an ambiguous error never flips the
  transport (fail-safe).
- One retry, ever: `outer_hop_plan.take()` consumes the plan; the kill switch
  is re-pinned to the relay endpoint before the second dial; `remote` is
  updated so firewall policy and logs name the relay, not the exit.
- `run_client` delegates to the engine path whenever
  `connection.outer_hop != OuterHop::None` (`run_circuit_client`).
- Mode gate: `stealth`, `Stealth MAX`, and `dynamic` may arm the fallback;
  `off`, `performance`, and `manual` never synthesize it.
- Acceptance test `it-outer-hop-fallback` (scripts/tests/rust/integration):
  real `ClientConnection` over a two-hop circuit, real `MasqueRelayOwner`
  association on loopback, inner QUIC bytes decode on the exit server. The
  pre-fallback dial and classifier are covered by engine unit tests; the test
  owns the post-fallback topology directly.
- Measured along the way: the outer `max_udp_payload` must exceed 1200 +
  flow-prefix for full-size inner Initials (test uses 1400; the nested-hop
  budget already subtracts `NESTED_MASQUE_OVERHEAD` per relay layer).
- Config comment in `config/quicfuscate.toml` states that a dedicated IP is
  not hidden by an outer hop.

## Risks

- Flapping between UDP and MASQUE creates two fingerprints. One failure, one fallback, then stick for the connection.
