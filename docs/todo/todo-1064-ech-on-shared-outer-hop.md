---
id: TODO-1064
title: ECH only on a shared outer hop
severity: LOW
phase: S
priority: P3
status: OPEN
created: 2026-09-21
depends_on: [TODO-1058, TODO-1063]
---

# TODO-1064: ECH only on a shared outer hop

## Why

RFC 9849 (2026-03) encrypts the inner ClientHello, including SNI. QUIC can carry it because the ClientHello sits in Initial. rustls 0.23 can do ECH as a client (`EchConfig`). Server-side rustls is still an open issue (rustls 1980). As of 2026-08, Cloudflare serves millions of ECH-capable domains over TCP and QUIC. On a dedicated VPN IP, ECH hides almost nothing: the IP is the name. RFC 9849 says the same.

## Current code

- rustls 0.23 is the TLS stack (`Cargo.toml`).
- Nothing constructs `EchConfig`.
- A grease ECH extension inside the synthetic hello does not count. TODO-1062 deletes that hello.

## Target

- Client ECH only on the outer hop from TODO-1063, and only when that hop's HTTPS/SVCB record contains an `ech` parameter.
- Fetch the record with DoH (TODO-1058), not cleartext DNS.
- If the record has no ECH config, connect without ECH. Do not invent a config.
- Do not implement server ECH while rustls server support is missing. The VPN listener does not pretend to speak ECH.

## Non-goals

- No custom HPKE.
- No frontend visual change.
- No ECH on the inner dedicated-IP listener.

## Design

1. After DoH, parse the HTTPS record. If `ech` is present, build `rustls::client::EchConfig` with the rustls HPKE provider and set it on the outer `ClientConfig`.
2. The direct UDP path to a dedicated IP does not set ECH.
3. Tests use a fixture record. Assert the client offers ECH when the fixture is present and does not when it is absent. Use the rustls API. Do not hand-roll the extension. A local server does not need to accept ECH if rustls still cannot be an ECH server.

## Sub-Tasks

- [ ] Confirm the pinned rustls 0.23 exposes `EchConfig`. If the lock is older, bump only within 0.23 and record the version. Do not fork and do not write a private ECH stack.
- [ ] Parse the HTTPS `ech` parameter from DoH.
- [ ] Outer client sets ECH only when the parameter exists.
- [ ] Tests: fixture present vs absent.
- [ ] Config comment: a dedicated IP gains nothing from ECH.

## Acceptance

- Outer hop with an ECH fixture offers ECH.
- Outer hop without a fixture does not.
- The inner listener has no ECH state.
- No hand-rolled ECH extension bytes.

## Risks

- The locked rustls 0.23 might predate client ECH. The version check is the first step. If the API is missing, this task stays blocked on a rustls bump.
