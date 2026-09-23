---
id: TODO-1055
title: QPACK, User-Agent, and server push only on the outer hop
severity: MEDIUM
phase: S
priority: P2
status: DONE
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

- [x] Preset audit: inner flags false.
- [x] Gate outer builder on hop type.
- [x] Test: inner connection sends zero server-push frames.
- [x] Test: MASQUE hop emits the persona's header names and debits the budget.

## Outcome (2026-09-27)

- `send_http3_request_headers` takes `outer_hop: bool`: inner `/tun` POST streams and
  functional requests emit pseudo + `x-qf-*` headers only; outer GET/MASQUE requests take
  the persona header list and debit the wire ledger for the encoded delta
  (`h3_header_list_bytes` + `try_spend_wire_cover`). MASQUE CONNECT-IP applies the same
  persona+budget path in `ensure_masque_tunnel_with_requirement`.
- `use_qpack_headers` is live: `init_http3` installs the persona dynamic-table capacity
  and index policy only when enabled; otherwise headers encode statically.
- Server push generation removed end to end: `generate_stealth_cover_burst`,
  `create_stealth_push_promise`, `process_scheduled_push_streams`, `process_push_data`,
  `push_streams`, `PushPromise`/`PushState`, `cover_content.rs`, `ServerPushState`,
  `ServerPushTriggerReason`, brain/orchestrator push triggers, `SERVER_PUSH_*` and
  `STEALTH_PUSH_*` telemetry, and `Event::PushPromise`.
- Receive side hardened per RFC 9114: no `MAX_PUSH_ID` is ever advertised, push streams
  (0x01) are rejected with `H3_STREAM_CREATION_ERROR`, `PUSH_PROMISE` is `H3_ID_ERROR`,
  and `CANCEL_PUSH`/`MAX_PUSH_ID` frames are parsed and dropped.
  Correction (2026-09-23): the historical client push-stream code above was
  wrong under RFC 9114 Section 4.6. TODO-1110 changed it to `H3_ID_ERROR`
  and proved the peer-received application close. The server's local rejection
  of a client-initiated push was already `H3_STREAM_CREATION_ERROR`.
- `enable_server_push_cover = true` in TOML is now a configuration error; the other
  `server_push_*` keys parse and are ignored. `QUICFUSCATE_SERVER_PUSH_COVER=true` warns.
- WebTransport cover is a one-shot outer-hop session emit claimed atomically per
  connection (`webtransport_cover_claimed`), decoupled from the deleted push scheduler.
- Cover-request scheduling moved to `StealthManager::cover_request_due()` — the scheduler
  returns `(authority, path)`, headers come from the persona fixture, one code path.
- New tests: `peer_push_streams_are_rejected`, `push_promise_without_max_push_id_is_rejected`,
  `max_push_id_grants_are_discarded`, `inner_tunnel_request_headers_carry_no_persona`,
  `outer_hop_request_headers_take_persona_and_rebuild_pseudo`,
  `outer_hop_persona_header_delta_debits_wire_budget`, `webtransport_cover_plan_is_a_one_shot`,
  `config_toml_rejects_enable_server_push_cover`.

## Acceptance

- A capture of an inner `stealth` flow shows no extra datagrams from `estimate_server_push_cover_bytes`.
- A MASQUE test still speaks HTTP/3.

## Risks

- Turning push off changes the size distribution. That is intended. Update any test that counted push packets as stealth success.
