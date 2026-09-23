---
id: TODO-1118
title: Reset QUIC loss recovery and congestion state after authenticated Retry
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: [TODO-1115]
---

# TODO-1118: Retry recovery-state reset

## Why and evidence

The real v2 Retry handshake added for TODO-1115 sends an Initial before
processing Retry. `src/transport/connection/recv.rs` then resets the Initial
packet-number space and rederives Initial keys, but leaves the old Initial
packet in `Recovery`, its bytes in flight, the congestion controller, and
pending loss/PTO timers. RFC 9002 Section 6.3 requires a client receiving
Retry to reset congestion control and loss recovery state, including timers,
while retaining cryptographic handshake messages. A fresh RFC 9000 Section
17.2.5.3 check also disproves the original plan's packet-number reset:
no packet-number space may reset after Retry, even though Initial keys change.
The existing pre-Retry test asserted zero as the next Initial packet number
and never sent an Initial, so it concealed both defects. RFC 9000 Section
17.2.5.2 additionally requires invalid tags, empty tokens and subsequent
Retries to be discarded without changing the connection.

## Target contract

- After one authenticated, accepted Retry, preserve the TLS transcript and
  retransmit every still-required Initial CRYPTO byte under the Retry SCID's
  freshly derived keys. Preserve the original DCID for Retry integrity and
  the subsequent transport-parameter binding in TODO-1120; the active
  destination CID and token are the Retry values.
- Reset all pre-Retry loss-recovery, bytes-in-flight, PTO and congestion-control
  state exactly once, while retaining the configured CC algorithm and live
  transport observer/FEC callback ownership. Preserve every next-send packet
  number, including Initial and Application/0-RTT, across Retry. Retire old
  recovery entries so ACK/loss processing cannot confuse pre- and post-Retry
  packets; the new Initial must use the next monotonic packet number.
  Reconcile 0-RTT stream transmission and replay state explicitly with RFC
  9000/9001; no early packet may be silently lost or counted twice. An
  accepted Retry permanently blocks new 0-RTT admission and packet emission
  for this connection attempt, even if a TLS provider later exposes early keys.
- Ignore a second Retry and a Retry after any authenticated server Initial;
  discard empty tokens, invalid integrity tags, mismatched Retry DCIDs and a
  Retry SCID equal to the original client DCID without mutating the live
  attempt. Do not replace a valid peer CID/token with unauthenticated input.

## Implementation and proof

- [x] Trace `Connection::recv` Retry branches, `Recovery` reset/discard APIs,
      packet-number counters, pending probes, 0-RTT queues, crypto-stream
      retransmission and callback installation. Read the actual signatures
      and keep one owner for the reset.
- [x] Add a real packet-pump test that sends Initial before authenticated v1
      and v2 Retry, records pre-Retry recovery and PTO state, then proves the
      old sent packet and timer are gone, the new Initial PN is strictly
      greater than the old one, and the full rustls handshake completes. Inject
      post-Retry loss and prove retransmission; the recovery unit test proves
      stale ACK rejection and new-packet ACK retirement.
- [x] Add negative tests for duplicate Retry, invalid tag, empty token, wrong
      DCID, repeated original DCID as SCID, and Retry after server Initial.
      Assert exact connection/token/CID/recovery
      immutability for rejected input, plus bounded 0-RTT behavior.
- [x] Update `docs/DOCUMENTATION.md` and `docs/MAP.md` with the measured Retry
      lifecycle and run focused transport, TLS, recovery, format and Clippy
      gates. Independent standards-wire proof remains with TODO-1095.

## Acceptance

- Zero pre-Retry sent packets, bytes in flight or timers survive into the new
  recovery state; all three packet-number spaces remain monotonic and the
  configured CC and callbacks remain attached. A real
  v1/v2 peer completes after Retry with correct CRYPTO retransmission and
  packet-number ownership under induced post-Retry loss.
- Rejected Retry input changes no connection state; accepted Retry mutates it
  once. 0-RTT disposition is explicit and covered by a failing test for each
  branch. Authenticating the retained CID history against the peer TLS
  transport parameters is the distinct TODO-1120 acceptance gate.

## Verification

- `cargo test --offline -p qf-transport-recovery --lib`: 53/53 passed.
- `cargo test --offline --lib transport::connection:: -- --quiet`: 160/160 passed.
- `cargo test --offline --lib core::connection:: -- --quiet`: 91/91 passed.
- `cargo test --offline --lib qftls:: -- --quiet`: 57 passed, 1 ignored.
- `cargo clippy --offline --lib -- -D warnings`, `cargo fmt --all -- --check`,
  and `git diff --check` passed. Full workspace, independent capture, and
  external peer interoperability were not run; TODO-1095 and TODO-1120 own
  their distinct protocol evidence.
