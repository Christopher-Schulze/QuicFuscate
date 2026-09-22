---
id: TODO-1058
title: DoH uses the same persona and is the only DNS
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-21
depends_on: [TODO-1047]
---

# TODO-1058: DoH uses the same persona and is the only DNS

## Why

DoH hides the destination name. It does not hide the VPN IP. It fails if a cleartext DNS query still leaves the host, or if the DoH ClientHello is a different stack than the tunnel persona.

## Current code

- `StealthConfig.enable_doh` and `doh_provider`.
- DNS implementation is `qf-dns` (DoH client plus UDP fallback).
- The tunnel persona does not force the DoH connection's TLS fingerprint.

## Target

- In `stealth`, `Stealth MAX`, and `dynamic`, UDP port 53 fallback is off. Failure is an error, not a silent cleartext query.
- The DoH connection uses the same persona builder as TODO-1047, aimed at the configured DoH host.
- `off` and `performance` may keep UDP fallback.
- Docs say in one line that DoH does not beat an IP block.

## Non-goals

- No new DNS protocol.
- No ECH here (TODO-1064). This task only stops the cleartext leak and aligns the persona.

## Design

1. `qf-dns` gains `allow_udp_fallback: bool`, set from the stealth mode.
2. DoH TLS setup calls the shared persona helper. The DoH client must be rustls. Do not add a second TLS stack.
3. A test resolver that refuses DoH must surface the error in stealth modes and must not send UDP. A mocked UDP send counts zero.

## Sub-Tasks

- [x] Mode flag wired into `qf-dns` — `DnsProxyConfig.allow_udp_fallback`;
      `process_dns_query` gates the upstream path before any socket work.
- [x] Persona shared with the tunnel hello builder — `doh_persona_ciphers`
      carries `profile_from_fingerprint(..).cipher_suites` into a
      preconfigured rustls `ClientConfig` on the pooled reqwest client.
- [x] Test: stealth plus DoH failure sends zero UDP/53 — real-send counter
      `UDP_FALLBACK_ATTEMPTS` stays flat under `allow_udp_fallback = false`.
- [x] Test: `off` still falls back — counter increments on the permitted path.

## Acceptance

- Stealth modes cannot emit a cleartext DNS query for the tunnel destination. —
  gate sits before `resolve_via_dns_upstreams_async`; SERVFAIL is returned.
- DoH TLS cipher list matches the persona fixture. —
  `test_persona_cipher_list_maps_onto_rustls_provider_order` asserts persona
  order on `crypto_provider().cipher_suites`; ALPN stays `h2` (the persona's
  `h3` is a QUIC advertisement no TCP client sends). TLS 1.2 suites keep
  rustls defaults — the fixture claims no 1.2 list.

## Risks

- Networks that block DoH fail closed in stealth modes. That is intended.
  `performance` remains the mode that may use UDP DNS.
- `use_preconfigured_tls` requires qf-dns's rustls to unify with reqwest's —
  Cargo.lock resolves a single `rustls 0.23.45`; verified by a successful
  persona client build in the policy-constructor test.
