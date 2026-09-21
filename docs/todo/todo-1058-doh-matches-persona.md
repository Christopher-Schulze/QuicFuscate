---
id: TODO-1058
title: DoH uses the same persona and is the only DNS
severity: MEDIUM
phase: S
priority: P2
status: OPEN
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

- [ ] Mode flag wired into `qf-dns`.
- [ ] Persona shared with the tunnel hello builder.
- [ ] Test: stealth plus DoH failure sends zero UDP/53.
- [ ] Test: `off` still falls back.

## Acceptance

- Stealth modes cannot emit a cleartext DNS query for the tunnel destination.
- DoH TLS cipher list matches the persona fixture.

## Risks

- Networks that block DoH fail closed in stealth modes. That is intended. `performance` remains the mode that may use UDP DNS.
