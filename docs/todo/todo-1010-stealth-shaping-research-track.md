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

## Implementation sketches (what "adopt" would mean in our code)

1. ChameleonFlow adaptation - `crates/qf-stealth/src/lib.rs` FlowShaper:
   a "restructure" mode holds a bounded reorder window (~5-15 ms) and emits
   real packets in structure-breaking order instead of buying chaff bytes.
   Natural fit: our outer datagrams are ours to shape (tunnel payload has
   no semantic packet boundaries). Anchor: `FlowShaper::apply_jitter` /
   `record_and_prune` and the send-loop batch drain. Success metric:
   equal-or-better WF-defense signal at near-zero bandwidth overhead vs
   chaff mode.

2. Adaptive-Tamaraw mapping - `crates/qf-stealth/src/intelligent_policy.rs`
   + StealthBrain policy table: add a per-flow-cluster parameter row
   {jitter_range, pad_rate, chaff_rate} selected by early time-series
   features we already collect (burst sizes, IAT histogram in
   `record_and_prune`'s 2 s window). Conservative global parameters remain
   the fallback until a cluster match is confident.

3. WF-A2D positions - make `apply_jitter`/`apply_flight_pacing`
   position-aware: burst head and burst boundaries carry the most WF
   signal. FlowShaper already tracks burst history; weight the
   perturbation by position-in-burst rather than uniformly.

4. QUICstep - design study only: path validation/migration exists
   (`PendingPathValidation`, transport config nat/migration). Handshake
   phase over a cover channel, migrate post-auth. If the study is adopted,
   it becomes its own multi-path plumbing TODO.

5. UPGen formalization - expose deployment-seeded wire-image parameters in
   the private-protocol config so two deployments do not share a shape
   signature; today seeds/epochs vary per connection, not per deployment.

## Acceptance
- Per candidate: adopt / adapt / reject with a written rationale in this
  file. Any adopted item becomes its own implementation TODO.
- Rejected candidates keep the numbers that killed them (so the decision
  stays auditable when the literature moves).

## Implementation status (2026-09)

ADAPTED - candidate 3 (WF-A2D positions) landed first because it needs no
new machinery: `FlowShaper::apply_jitter` is now position-aware via
`is_burst_edge` - the first packet after a >=100 ms idle gap (or the very
first packet) samples the full jitter range while burst-interior packets
stay in the tight low half. Perturbation budget now lands on burst
boundaries where WF classifiers extract their signal. Deterministic test
`flow_shaper_widens_jitter_at_burst_edges` proves the contract with the
injected `ManualTimeSource`.

ADAPTED - candidate 1 (ChameleonFlow "shape what's there") partially:
`derive_intelligent_runtime_policy` now halves `padding_rate` when
ACK-clocked traffic is dense (`ack_us < 3_000`) - real packets already
carry burst structure, so purchased chaff only widens the bandwidth
footprint. Regression `dense_traffic_halves_padding_rate` covers both
branches. The full ChameleonFlow reorder-window variant (redistribute real
packets across time instead of adding chaff) stays open - it needs a
bounded delay queue in the send path, which is a bigger surgery than the
rate rule.

ADAPTED - candidate 2 (Adaptive Tamaraw) partially:
`intelligent_policy.rs` now classifies traffic into `TrafficPhase`
(Dense/Sparse/BurstEdge on smoothed `ack_us`; the brain's EMA supplies the
hysteresis) and reads jitter scale from the phase table: dense 0.4, sparse
0.6 (external pacing), burst-edge 0.85. Before, the split was a flat
0.6/0.4 on `external_pacing` alone. The pairing is now coherent per phase -
dense traffic stays tight because the real stream masks itself, idle and
bursty phases get maximum jitter because burst edges carry the
fingerprint. Test `tamaraw_phase_table_scales_jitter_by_density` pins both
branches. A literal per-cluster (rho, gamma) row with disjoint upload vs
download weights stays open: our policy is symmetric today, so the table
has one axis; splitting it needs direction-aware signal plumbing
(up/down ack density separately).

OPEN: candidates 4, 5 unchanged (QUICstep design study, UPGen deployment
seeding); the full ChameleonFlow reorder window stays open per above.
