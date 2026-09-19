---
id: TODO-1006
title: Audit whether wire-level FEC recovery masks congestion loss from congestion control (RFC 9265)
severity: MEDIUM
phase: S
priority: P2
status: OPEN
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

## Investigation
- Trace whether a FEC-recovered PN still reaches the loss detector / CC as a
  loss event (e.g. via wire-gap statistics reported back, or the ACK arriving
  after the loss declaration deadline anyway).
- If recovery masks loss: either feed a wire-loss estimate into CC
  (companion to `recovery_loss_rate()`), or document the trade-off
  explicitly as an intentional design choice with its bounds (only losses
  within FEC capacity are hidden; losses beyond still hit CC).
- Check draft-zheng-quic-fec-extension's Repair-ACK idea as prior art:
  receiver reports FEC-recovered sources so the sender can both suppress
  retransmission and still count the loss for CC.

## Acceptance
- Documented verdict in this file: masked or not masked, with the exact code
  path proving it.
- If masked: either CC visibility restored or a deliberate-behavior note
  with the masking bound (recovery capacity) written down.
