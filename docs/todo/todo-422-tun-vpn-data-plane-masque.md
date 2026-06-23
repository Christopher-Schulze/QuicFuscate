---
id: TODO-422
title: TUN VPN data plane end-to-end via MASQUE (CONNECT-UDP capsule <-> TUN routing)
severity: HIGH
phase: "2"
priority: P1
status: OPEN
created: 2026-06-23
depends_on: []
---

# TODO-422: TUN VPN Data Plane End-to-End (MASQUE Routing)

## Goal

Make a real packet traverse the tunnel end-to-end: a `ping` from the client's TUN
device reaches the server's TUN device and the reply comes back. Today the QUIC+TLS
handshake completes in both directions (cert validation, no panic, loss 0.00%), but
no user data flows through the TUN bridge.

## Decision: Option A (MASQUE) — chosen

The tunnel payload is carried as **MASQUE HTTP/3 DATAGRAM capsules (CONNECT-UDP)** in
both directions. Rejected alternative: Option B (raw H3 DATA-frame tunneling).

| | Stealth | Performance | Effort |
|---|---|---|---|
| **A MASQUE (chosen)** | best — looks like a legit CONNECT-UDP proxy, not a VPN | best — datagram, no head-of-line blocking | higher |
| B DATA frames | weaker — endless POST upload is conspicuous | worse — reliable ordered stream = HoL blocking stalls all packets on one loss | lower |

Rationale: stealth + low-latency datagram transport are the core project goals, so the
HoL blocking and weaker cover of Option B are disqualifying for real VPN traffic.

## Current State (what works / what is broken)

Verified on `broderick` with two network namespaces over a veth pair (single-host
loopback short-circuits TUN routing, so netns is mandatory for this test).

Works:
- Handshake completes over veth+TUN (client + server both log "TLS handshake complete").
- Client uplink read path: client TUN reader reads IP packets (ICMP 84B) and calls
  `http3_send_body_chunk` (src/main.rs client loop).
- Server downlink read path: server TUN reader reads packets and forwards them to the
  run-loop via the `tun_rx` channel, which calls `dgram_send` (src/implementations/server/mod.rs).

Broken (the architectural mismatch):
- **Uplink delivery:** `core::QuicFuscateConnection::http3_send_body_chunk` (src/core.rs:1164)
  prefers the MASQUE path (`ensure_masque_tunnel_for_send` -> `h3.send_masque_datagram`).
  The server receives these as `Event::MasqueCapsule` in `poll_http3_event_loop`
  (src/core.rs:654) but **never routes them to the TUN**. The server only writes to TUN
  from (a) the regular H3 DATA-frame `on_body` callback and (b) the raw `dgram_recv` loop,
  in `process_live_server_client_datagram` (src/implementations/server/mod.rs ~1945-1975).
  So uplink MASQUE capsules are dropped.
- **Downlink delivery:** server `dgram_send(&raw_ip_packet)` is sent, but the client's
  `dgram_recv` loop in the TUN branch (src/main.rs) receives 0 — the server forwards via
  bare QUIC datagrams while the client expects... the path is not consistent end-to-end.

So neither direction has a single, consistent transport wired through to the TUN on both
ends.

## Prerequisites already fixed (commit 8085f9b, this dependency chain)

- Client TUN reader no longer deadlocks the downlink writer (Arc<TunInterface> + write()).
- `h3.recv_body()` returns real buffered DATA-frame payload (was a `b"Response body"` stub);
  `process_stream` now buffers DATA into `StreamState.body_buffer` and records peer streams.
  (These mainly help the Option-B path but are correct standalone fixes; keep.)

## Implementation Plan (Option A)

The unit of transport is one MASQUE CONNECT-UDP datagram carrying exactly one raw IP packet.

### 1. Client uplink (already mostly there)
- Keep `http3_send_body_chunk` -> `send_masque_datagram` for TUN frames (one IP packet per
  HTTP/3 DATAGRAM). Confirm `ensure_masque_tunnel_for_send` establishes the CONNECT-UDP flow
  once and reuses its flow/context id.

### 2. Server uplink: MASQUE capsule -> TUN  (CORE MISSING PIECE)
- In the server's H3 event handling (`poll_http3_with_headers` / the MASQUE datagram
  callback used by `poll_http3_event_loop`), deliver the decoded CONNECT-UDP payload to a
  sink. Wire that sink to `server_tun.write(payload)` in
  `process_live_server_client_datagram` (mirror the existing DATA-frame `on_body` -> TUN write,
  but for MASQUE datagrams/capsules).
- Use the existing MASQUE datagram callback path (`bindings.masque_datagram_cb` /
  `handle_masque_capsule_event` / `drain_masque_datagrams` in src/core.rs ~654-709) rather
  than the raw `dgram_recv` loop, so framing (quarter-stream-id + context-id) is stripped and
  only the raw IP packet reaches the TUN.

### 3. Server downlink: TUN -> MASQUE
- Replace the server run-loop's `dgram_send(&pkt)` (src/implementations/server/mod.rs ~4120)
  with a MASQUE datagram send on the client's established CONNECT-UDP flow
  (`h3.send_masque_datagram` for that connection's flow id), so the downlink uses the SAME
  transport as the uplink. Track the per-client MASQUE flow id when the client establishes it.

### 4. Client downlink: MASQUE capsule -> TUN
- In the client loop (src/main.rs TUN branch), drain MASQUE datagrams (via
  `poll_http3_with` / the MASQUE datagram callback) and write the raw IP payload to the client
  TUN, instead of (or in addition to) the current bare `dgram_recv` loop. Remove the
  inconsistent bare-datagram downlink once MASQUE is wired.

### 5. Consistency / cleanup
- One transport (MASQUE CONNECT-UDP datagrams) for both directions on both ends.
- Remove the now-dead raw `dgram_recv` -> TUN paths if they are not used by anything else.
- Ensure the auth gate (`require_auth && !authed`) is satisfied for the MASQUE flow (the
  client must present the QKey so the server forwards its datagrams to TUN).

## Files to touch
- src/core.rs — `http3_send_body_chunk`, MASQUE datagram callbacks/bindings, downlink send helper.
- src/implementations/server/mod.rs — `process_live_server_client_datagram` (MASQUE->TUN sink),
  run-loop TUN->client send (dgram_send -> MASQUE send), per-client MASQUE flow tracking.
- src/main.rs — client TUN branch downlink (MASQUE capsule -> TUN write).
- src/transport/h3.rs — only if MASQUE capsule/datagram plumbing needs a sink hook.

## Acceptance Criteria
- `ip netns exec ns-cli ping -c5 10.0.1.1` through the tunnel: **0% packet loss**.
- Both sides still log "TLS handshake complete"; no panics; loss stays ~0.
- Uplink AND downlink both carried over MASQUE CONNECT-UDP (verified via logs/telemetry:
  `MASQUE_BYTES_RECEIVED` / capsule counters increment on both ends).
- `cargo build --release` clean, `cargo clippy --lib -D warnings` green.

## Test Harness
- `scripts/` netns harness (current ad-hoc version lives at `/tmp/netns-tun.sh` on broderick;
  promote it to `scripts/tests/` as `tun-e2e-netns.sh`): creates ns-srv/ns-cli + veth, starts
  server+client with `--tun`, configures TUN IPs/routes, pings through the tunnel.
- Server cert SAN must list all Cloudflare front domains the client may validate against
  (cdn.cloudflare.com, cloudflare-dns.com, one.one.one.one, warp.plus, workers.dev) because the
  client validates the peer cert against a randomly chosen front SNI
  (CdnProvider::Cloudflare::get_domains, src/stealth/mod.rs ~1999).

## Notes
- NOT to be done in the current session (deferred by user decision).
- The handshake, cert validation (incl. --ca-file), server H3 OOB panic, idle-timeout/loss
  inflation, and client Finished delivery are all already fixed and on `main`.
