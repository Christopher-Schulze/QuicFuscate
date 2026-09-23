---
id: TODO-1118
title: Reset QUIC loss recovery and congestion state after authenticated Retry
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1115]
---

# TODO-1118: Retry recovery-state reset

## Why and evidence

The real v2 Retry handshake added for TODO-1115 sends an Initial before
processing Retry. `src/transport/connection/recv.rs` then resets the Initial
packet-number space and rederives Initial keys, but leaves the old Initial
packet in `Recovery`, its bytes in flight, the congestion controller, and
pending loss/PTO timers. The new Initial reuses packet number zero, so stale
recovery state can collide with its replacement even when a no-loss loopback
handshake happens to finish. RFC 9002 Section 6.3 requires a client receiving
Retry to reset congestion control and loss recovery state, including timers,
while retaining cryptographic handshake messages. The existing pre-Retry test
never sent an Initial and therefore could not see this state.

## Target contract

- After one authenticated, accepted Retry, preserve the TLS transcript and
  retransmit every still-required Initial CRYPTO byte under the Retry SCID's
  freshly derived keys. Preserve the original DCID solely for Retry integrity
  and transport-parameter binding; the active destination CID and token are
  the Retry values.
- Reset all pre-Retry loss-recovery, bytes-in-flight, PTO and congestion-control
  state exactly once, while retaining the configured CC algorithm and live
  transport observer/FEC callback ownership. Do not mix old and new Initial
  packet-number epochs. Reconcile 0-RTT stream transmission and replay state
  explicitly with RFC 9000/9001; no early packet may be silently lost or
  counted twice.
- Ignore a second Retry and a Retry after any authenticated server Initial;
  reject empty tokens and invalid integrity tags without mutating the live
  attempt. Do not replace a valid peer CID/token with unauthenticated input.

## Implementation and proof

- [ ] Trace `Connection::recv` Retry branches, `Recovery` reset/discard APIs,
      packet-number counters, pending probes, 0-RTT queues, crypto-stream
      retransmission and callback installation. Read the actual signatures
      and keep one owner for the reset.
- [ ] Add a real packet-pump test that sends Initial before authenticated v1
      and v2 Retry, records pre-Retry recovery and PTO state, then proves the
      old sent packet and timer are gone, PN zero belongs only to the new
      epoch, and the full rustls handshake completes. Inject loss/reordering
      after Retry and prove retransmission and ACK retirement.
- [ ] Add negative tests for duplicate Retry, invalid tag, empty token and
      Retry after server Initial. Assert exact connection/token/CID/recovery
      immutability for rejected input, plus bounded 0-RTT behavior.
- [ ] Update `docs/DOCUMENTATION.md` and `docs/MAP.md` with the measured Retry
      lifecycle and run focused transport, TLS, recovery, format and Clippy
      gates. Independent standards-wire proof remains with TODO-1095.

## Acceptance

- Zero pre-Retry sent packets, bytes in flight or timers survive into the new
  recovery epoch; the configured CC and callbacks remain attached. A real
  v1/v2 peer completes after Retry with correct CRYPTO retransmission and
  packet-number ownership under induced post-Retry loss.
- Rejected Retry input changes no connection state; accepted Retry mutates it
  once. 0-RTT disposition and transport-parameter identity are explicit and
  covered by a failing test for each branch.
