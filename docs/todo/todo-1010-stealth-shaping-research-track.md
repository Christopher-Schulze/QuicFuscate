---
id: TODO-1010
title: Next-generation stealth shaping - research track from 2025 literature
severity: MEDIUM
phase: L
priority: P2
status: OPEN
created: 2026-09-19
depends_on: []
---

# TODO-1010: Stealth shaping research track

## Objective
Standing stealth task: evaluate four 2025 research directions against the
current FlowShaper/StealthBrain/TLS-Cover/chaff stack and adopt what wins.

## Candidates (with what the literature claims)

1. **ChameleonFlow (MLCIPR 2025)** - padding-free WF defense: instead of
   adding bytes, redistribute the same packets across multiple QUIC
   streams/time windows to destroy burst structure. Reported: WF
   classifier accuracy 96.3% -> 35.8% at only 8.7% bandwidth / 11.2%
   latency overhead (5x more efficient than padding defenses). Our DATAGRAM
   path has no stream layer to reshuffle into, but the same idea applies at
   the packet-train level: reshaping inter-burst structure without dummy
   bytes. Worth a design note: can FlowShaper reorder/space real packets to
   break burst fingerprints instead of paying chaff bandwidth?

2. **Adaptive Tamaraw (2025, arXiv 2509.01046)** - cluster-based adaptive
   padding: group flows into (k,l)-diverse anonymity sets, classify early
   into the set, then apply set-specific (lighter) padding parameters.
   Keeps Tamaraw's information-theoretic bound while cutting overhead by
   ~99 percentage points in efficiency mode. Maps directly onto
   StealthBrain's controller: per-flow-class shaping parameters instead of
   global jitter/padding knobs.

3. **WF-A2D (TIFS 2025)** - asymmetric adversarial defense: position-based
   perturbation vectors for packet-level manipulation, <2% bandwidth
   overhead, ~97% defense rate against 7 SOTA analyzers, client-side only.
   Our `probe_detector` + FlowShaper could adopt position-aware
   perturbation (where in the train a pad/delay lands matters more than
   how much).

4. **QUICstep / CoMPS (PETS 2026)** - connection-migration traffic
   splitting: route handshake + early packets over one path (e.g. a cover
   proxy), migrate the data phase elsewhere. Reported to defeat real QUIC
   SNI censors while reducing cover-channel load. Our multi-path/migration
   support exists for robustness; re-purposing it as a censorship-defense
   primitive is a design study, not new plumbing.

5. **UPGen (2025)** - unidentified protocol generation: generate
   per-deployment protocol variants that classify as "unknown benign
   encrypted" rather than a known circumvention protocol. Long-term idea:
   parameterizable wire-image diversity (our private-protocol mode already
   varies; UPGen formalizes why per-deployment variance raises collateral
   cost for censors).

## Anti-goals / reality checks
- Domain fronting is dead on major CDNs (2018+) - keep
  `DomainFrontingManager` documented as fallback-only or consider archival.
- GFW QUIC SNI blocking is real but residual-only + compute-limited
  (USENIX Sec '25): our custom handshake avoids standard Initial format;
  keep it that way and note that Initial-decryption pressure is
  time-of-day dependent.
- HotNets'25 argues shaping belongs in the network stack for fine-grained
  control - our kernel-level pacing/io_uring timing hooks align; prefer
  precision timing at the send syscall boundary over userspace sleep loops.

## Acceptance
- Per candidate: adopt / adapt / reject with a written rationale in this
  file. Any adopted item becomes its own implementation TODO.
