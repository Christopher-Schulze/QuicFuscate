---
id: TODO-1116
title: Route disguise-migration traffic through both observed UDP paths
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1056]
---

# TODO-1116: Disguise-migration socket and path routing

## Why and evidence

`src/main/runtime/client.rs` creates `standby_socket` and replaces the active
connected UDP socket as soon as `begin_disguise_migration(new_local)` starts.
Its `tokio::select!` has one receive branch, `recv_connected_burst(&socket)`;
the standby socket is never read before validation succeeds or fails.
That branch calls `conn.recv_mut`, which in `src/core/connection.rs` forwards
`self.local_addr` as `RecvInfo.to`. The core changes `self.local_addr` only
after a `PathEvent::Validated`, so a PATH_RESPONSE received on the new socket
before validation is reported to the transport as arriving on the old local
path. `src/transport/connection/recv.rs` passes `info.to` to
`handle_path_response_frame`, making the path identity relevant to the
validation result. Independently, the connected send helpers in
`src/main.rs::flush_connected_outgoing` call `conn.send`; that compatibility
method discards `send_with_info`'s `SendInfo.from/to`, and all output is sent
through the supplied socket. Packets the transport assigns to the old path
cannot be delivered by that helper while the new socket is active. These
source-observed mismatches invalidate the claim that merely holding the old
socket open preserves in-flight traffic. A captured failure/success outcome
has not yet been reproduced; the path-aware integration test is required.

## Target contract

- During local-port migration, the runtime owns exactly the old and candidate
  sockets until the transport reports validation success or failure. It polls
  both without starving either. Every received datagram is passed to
  `recv_on_path_mut` with the actual socket's local address and authenticated
  connected peer; GRO segments retain that same observed path.
- Every emitted datagram uses `send_with_info` and is dispatched by the
  transport-selected `SendInfo.from/to`. A path-control probe for the candidate
  uses the candidate socket; packets assigned to the old validated path use
  the old socket. Never silently send a packet from a different local port.
  Preserve pacing timestamp and Linux batching/GSO only within identical
  source/destination path groups; a mixed-path burst must not be coalesced.
- On validation success, commit the candidate socket only after path events
  and CID state agree; on failure or timeout, restore the old socket and
  discard the candidate without leaving a stale pending migration. Keep app
  traffic, ACK/PTO, PMTU and kill-switch route handling live throughout.
  The next due timer is redrawn exactly once per settled attempt.
- This task proves functional migration and rollback. TODO-1086 separately
  enforces fresh peer CID and privacy/cadence prerequisites. Do not use a
  successful new-port test as proof of unlinkability.

## Implementation and proof

- [ ] Trace `begin_disguise_migration`, path event generation, `SendInfo`,
      `conn.send_with_info`, both `flush_connected_outgoing` variants,
      GRO receive, and connected socket ownership with their actual
      signatures and path-state transitions.
- [ ] Use the existing path-aware core APIs for both sockets; adapt the
      client event loop and send helper in place. Keep one immutable mapping
      from each live local endpoint to its socket, and prohibit an unknown
      `SendInfo.from` from falling back to the active socket.
- [ ] Add a real loopback two-socket integration test: old-path application
      data arrives while candidate validation is pending; candidate
      PATH_CHALLENGE/RESPONSE is observed on the new port and validates;
      mixed-path outgoing packets use their selected socket. Repeat with
      dropped PATH_RESPONSE and with send/recv errors to prove rollback,
      uninterrupted old-path delivery and one-shot cleanup.
- [ ] Capture both client sockets and server ingress during success/failure;
      assert 4-tuple, path frame direction, no new Initial/handshake, zero
      cross-path attribution, and no unbounded packet queue. Run Linux
      GSO/GRO and macOS ordinary-datagram gates separately. Update
      `docs/DOCUMENTATION.md`, `docs/MAP.md`, TODO-1056 result wording and
      TODO-1086 prerequisites to the actual evidence.

## Acceptance

- 100% of received packets during migration carry their observed local path
  into transport, and 100% of emitted packets use their selected path.
  The old socket remains read/write capable until validation settles.
- Candidate path validation succeeds with a real PATH_RESPONSE on its port;
  failure/timeout returns to the old usable path without losing the session.
  Loopback integration and two-sided capture prove both outcomes, while
  TODO-1086's CID/privacy gate remains separately open.
