---
id: TODO-1006
title: Audit whether wire-level FEC recovery masks congestion loss from congestion control (RFC 9265)
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-19
depends_on: []
---

# TODO-1006: FEC recovery vs congestion-signal visibility

## Objective
Audit and, if needed, correct the interaction between wire-level FEC recovery
and congestion control. QuicFuscate's FEC operates below QUIC: source
datagrams pass through unchanged (systematic code), repair packets recover
lost wire datagrams, and `WireFecReceiver` re-injects recovered packets into
`conn.recv`. A PN recovered this way gets ACKed normally - the sender's QUIC
loss detector then never declares it lost, so the congestion controller sees
a cleaner path than the wire actually delivered.

RFC 9265 ("FEC Coding and Congestion Control in Transport") warns exactly
about this: FEC must not hide congestion loss signals, or the sender keeps
pushing into a congested path and worsens it. Today `fec_cb_lost_packets`
feeds only the adaptive FEC controller; whether the QUIC CC still observes
wire loss for recovered PNs is unverified.

## Implementation plan

Phase 1 - Trace (read-only, no code changes):
- `src/transport/connection/api.rs:install_recovery_fec_callbacks` wires
  `fec_cb_sent/lost` callbacks into the recovery module. Find the firing
  site: the lost callback fires when the QUIC loss detector *declares* a PN
  lost (PN-gap + time-threshold), not when the wire dropped it.
- `src/core/connection.rs:~1001` `fec_wire_receiver.receive(data,
  recovered_packets)` emits `WireDelivery::{Borrowed,Owned}` slices into
  `conn.recv` - a recovered PN is then ACKed normally by the receiver.
- Question A: if the receiver ACKs a recovered PN before the sender's
  loss-declaration window closes, the PN is acked-first and the loss event
  never fires - the wire loss is invisible to CC. Confirm by reading the
  loss-declaration path in the recovery module (where `fec_cb_lost_packets`
  increments vs where ACK processing removes in-flight PNs).
- Question B (self-blinding check): `recovery_loss_rate()` feeds the
  adaptive FEC controller. If it derives from *declared* losses, successful
  recovery shrinks the measured loss rate exactly when FEC is working -
  the controller could under-protect under sustained loss. Verify what the
  estimator counts.

Phase 2 - Deterministic test:
- New rt-test: controlled loss burst inside FEC repair capacity. Assert
  (a) stream data delivered without retransmission (recovery works),
  (b) whether the sender-side loss detector/CC observed the wire loss
  (cwnd/loss counter), (c) `recovery_loss_rate()` still reflects wire loss.

Phase 3 - Fix options (choose after Phase 1 verdict):
- (a) Sender-side wire-loss channel: `WireFecReceiver` knows recovered
  source IDs (`emit_recovered`, global_id); receiver reports them in an
  ACK-adjacent metadata frame (draft-zheng-quic-fec-extension Repair-ACK
  prior art); sender counts wire loss for CC while suppressing
  retransmission. Most correct, needs wire format addition.
- (b) Estimator fusion: fold the receiver-reported recovery rate into
  `recovery_loss_rate()` as a corrected loss estimate - cheaper, no wire
  change, approximate.
- (c) Documented acceptance: masking is bounded by repair capacity
  (losses beyond capacity still declare normally); if the bound is
  acceptable for a private VPN transport, write it down here and in
  DOCUMENTATION.md instead of building (a)/(b).

## Risks
- Fixing (a) touches the wire format - version/negotiation care needed.
- (b) is a heuristic; a wrong correction term could over-signal loss and
  throttle unnecessarily.

## Acceptance
- Documented verdict in this file: masked or not masked, with the exact
  code path proving it.
- If masked: either CC visibility restored (option a or b) or a
  deliberate-behavior note with the masking bound (repair capacity)
  written down.
- Regression: qf-fec suite + `fec_decode16_elimination` bench green.

## Verdict (2026-09-19): masked, but tightly bounded - accepted with
## observability; Repair-ACK deferred

Code trace confirming the mechanism:

- `crates/qf-transport-recovery/src/lib.rs:detect_lost_packets` runs inside
  `on_ack_received` and declares loss only for PNs still in `sp.sent` past
  the packet/time thresholds. A PN the receiver recovered via FEC is
  ACKed normally (the recovered datagram re-enters `conn.recv`), so if the
  ACK arrives before the declaration window closes, the loss event never
  fires - invisible to both the loss callback (`fec_cb_lost_packets`) and
  the congestion controller.
- Bound: masking applies only to losses recovered faster than
  `loss_delay` (time-threshold ~ RTT scale). A PN whose ACK arrives after
  declaration is a *spurious* loss - CC already backed off, which is the
  conservative (RFC-9265-safe) direction. Losses exceeding repair capacity
  are never masked at all.
- Controller inputs are already correct on both axes: the receiver-side
  `AdaptiveFec` gets wire truth via `observe_wire_receive(receive_report)`
  (`src/core/connection.rs:1141`), and the sender side regulates on
  *residual* (post-recovery) declared loss - which is the desired control
  target, not a bug: the controller should drive unrecovered loss toward
  zero, not chase raw wire loss it cannot see anyway.
- Observability exists: `quicfuscate_fec_packets_recovered` is exported
  (Prometheus export + admin JSON), so masked-loss volume is measurable
  as (recovered) vs (declared lost).

Decision: option (c) documented acceptance. For a private VPN transport the
bounded masking is defensible - the hidden signal is exactly the slice FEC
repaired quickly, and congestion-grade loss always exceeds repair capacity
and reaches CC unmasked. Option (a) Repair-ACK remains the only complete
fix and is recorded as a deferred wire-format enhancement in TODO-1011
item 3 (the receiver-side `recovered_ids()` reporting half is tracked
there; the sender-side CC accounting lands only if that work happens).
