---
id: TODO-978
title: Standalone client: downlink waited on 250ms housekeeping tick
status: DONE
created: 2026-09-18
---

# TODO-978 - Standalone client: downlink waited on 250ms housekeeping tick

Status: DONE (local tests + Omega aarch64 Linux hop-measurement)

## Problem

TUN end-to-end latency showed a hard ~252ms floor in both directions
(mdev ~0.4ms - a fixed timer, not jitter). Three-hop packet captures
(veth-cli, qtun0-cli, qtun0-srv) localized it precisely:

```
ICMP req   qtun0-cli     t+0.00ms   ping start
UDP dgram  cli->srv      t+0.14ms   client uplink fast
ICMP req   qtun0-srv     t+0.18ms   server recv->TUN fast
ICMP reply qtun0-srv     t+0.03ms   kernel turnaround
UDP dgram  srv->cli      t+0.14ms   server downlink fast
ICMP reply qtun0-cli     t+251.5ms  <-- delay inside client
```

The server answered within microseconds on the wire; the datagram then
sat ~251ms inside the client process before reaching `qtun0`.

Root cause: `conn.recv()` in the UDP-receive select branch only decodes
QUIC packets and queues H3/MASQUE events internally. The actual dispatch
(`h3.try_recv_masque_datagram` -> `masque_datagram_cb` -> TUN write) runs
inside `poll_http3_event_loop`, which the standalone client invoked ONLY
from the housekeeping branch. With no other activity,
`client_housekeeping_delay` returns `CLIENT_HOUSEKEEPING_IDLE` (250ms),
so every downlink payload waited for the next tick.

A/B isolation: `enable_pacing=false` E2E kept the ~252ms RTT, ruling out
the BBR3 startup-floor/OutboundPacer hypothesis. The `io_driver` client
already polls `poll_http3_to_ingress` after every `conn.recv` - only the
standalone runtime had the gap.

## Fix

`src/main/runtime/client.rs`:

- New `client_h3_downlink_body_cb` helper builds the TUN-write body sink
  once for both call sites (was an inline closure in the housekeeping
  branch).
- The UDP-receive branch now calls `conn.poll_http3_with(...)` (TUN mode)
  or `conn.poll_http3()` (non-TUN) immediately after a successful
  `conn.recv`, before `flush_connected_outgoing` so H3-generated egress
  is emitted in the same flush. `ensure_http3_ready_for_poll` keeps the
  pre-handshake call a cheap no-op and accelerates deferred H3 init.
- The housekeeping branch calls the same helper - unchanged semantics,
  now a shared fallback for events that surface without a datagram.

## Proof

- `cargo check --bin quicfuscate` clean, clippy clean, fmt clean.
- `cargo test --bin quicfuscate`: 50/50.
- Omega manual netns run, three-hop captures, default config (BBR3 +
  pacing on): cli->srv 0.540/0.564/0.598ms, srv->cli 0.414/0.573/0.654ms
  (was ~252ms both directions before the fix).
- Omega `scripts/tests/tun-e2e-netns.sh` PASS on 0ca37d9: handshake both
  sides, 0% loss, cli->srv rtt 0.368/0.439/0.585ms, srv->cli
  0.325/0.429/0.480ms, forwarding restored, no TUN/firewall residue.
- Commit: 0ca37d9.
