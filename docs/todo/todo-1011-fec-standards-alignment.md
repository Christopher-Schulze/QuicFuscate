---
id: TODO-1011
title: FEC standards alignment - NWCRG RLC window, application-tailored gating, repair feedback
severity: MEDIUM
phase: M
priority: P2
status: OPEN
created: 2026-09-19
depends_on: []
---

# TODO-1011: FEC maximal-effectiveness alignment

## Objective
Standing FEC task: align qf-fec with what the 2024-2026 literature +
IETF/IRTF direction shows as effective, and squeeze remaining overhead.

## Findings to evaluate

1. **Application-tailored activation (QUIRL, TNET 2024)** - first QUIC-FEC
   work with real-network wins: FEC only for latency-sensitive data,
   retransmission otherwise; tail latency improved without hurting
   loss-free paths. Our Kalman-adaptive controller already scales
   redundancy by observed loss; check whether per-stream/per-priority
   gating (protect latency-critical streams only, bulk flows rely on
   retransmission) buys more efficiency than global adaptation.

2. **Sliding-window RLC standardization (draft-roca-nwcrg-rlc-fec-scheme-
   for-quic, Coding4QUIC framework)** - TinyMT32-seeded coefficients,
   sliding encoding window, negotiated via transport parameters. Our RLNC
   already does windowed coding; aligning coefficient generation/wire
   metadata with the draft would future-proof interop and let us reuse
   their analysis. Worth a diff-review of our `fountain_codes`/`variants`
   coefficient PRNG vs TinyMT32 design rationale.

3. **Repair-ACK feedback (draft-zheng-quic-fec-extension)** - receiver
   tells sender which sources FEC recovered; sender suppresses redundant
   retransmission and can count the loss for CC (pairs with TODO-1006).
   Check whether our wire receiver can report recovered source IDs back
   cheaply (small side-channel or folded into ACK-adjacent metadata).

4. **Convolutional/overlapping generations (rQUIC)** - overlap coding
   windows so repair capacity spreads uniformly instead of block-aligned;
   rQUIC reports latency gains vs block codes under burst loss. Our
   interleaved/streaming-burst variants may already approximate this -
   document the gap analysis rather than assume.

5. **Unequal protection** - draft-zheng recommends selecting which data
   gets FEC (not equal protection of everything). Our policy layer has
   per-epoch profiles; confirm latency-sensitive classes (control, early
   handshake completion, TUN-encapsulated DNS/ICMP) get protection while
   bulk doesn't.

## Acceptance
- Written adopt/adapt/reject per item with code references.
- Any adopted mechanism becomes its own implementation TODO.
- Regression: `fec_decode16_elimination` bench and qf-fec suite stay green.
