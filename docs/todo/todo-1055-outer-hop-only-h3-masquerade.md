---
id: TODO-1055
title: QPACK, User-Agent, and server push only on the outer hop
severity: MEDIUM
phase: S
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-1052]
---

# TODO-1055: QPACK, User-Agent, and server push only on the outer hop

## Why

Inside the tunnel those bytes sit under AEAD. A passive observer never reads "Chrome/153". They only see the length change. Server push adds packets with their own sizes. That spends the wire budget on a string nobody on the censor path can read.

## Current code

- `StealthConfig.use_qpack_headers`, `enable_http3_masquerading`, `enable_server_push_cover`, `server_push_intensity`, `server_push_base_path`, `server_push_burst_interval`.
- `estimate_server_push_cover_bytes` in `src/stealth/manager.rs`.
- Performance, stealth, and stealth-max presets turn masquerade, QPACK, and push on at different intensities.
- MASQUE / HTTP/3 on the outer hop is a separate path (`src/transport/h3`, `src/implementations/server/masque_relay.rs`). That path is where a middlebox could see HTTP/3.

## Target

- Inner TUN flow: `use_qpack_headers`, masquerade headers, and server push are off. No fake push packets.
- Outer hop, only when the connection is MASQUE or a real H3 request toward a cover target: QPACK and header names follow the same persona fixture as TODO-1047. Length delta is charged to TODO-1052. If the outer hop is a raw QUIC UDP socket to a dedicated port, masquerade stays off there too.
- User-Agent strings remain in the persona catalog as the source for that outer request. They are not copied into inner streams.

## Non-goals

- No new HTTP stack.
- No frontend visual change.

## Design

1. Split the flags into inner (force false) and outer (true only if the dial target is an H3/MASQUE hop).
2. Presets stop setting push intensity above 0 for the inner connection. The `stealth_max()` push intensity goes away.
3. Outer request builder reads the persona header list and encodes it with the existing QPACK encoder. One code path.

## Sub-Tasks

- [ ] Preset audit: inner flags false.
- [ ] Gate outer builder on hop type.
- [ ] Test: inner connection sends zero server-push frames.
- [ ] Test: MASQUE hop emits the persona's header names and debits the budget.

## Acceptance

- A capture of an inner `stealth` flow shows no extra datagrams from `estimate_server_push_cover_bytes`.
- A MASQUE test still speaks HTTP/3.

## Risks

- Turning push off changes the size distribution. That is intended. Update any test that counted push packets as stealth success.
