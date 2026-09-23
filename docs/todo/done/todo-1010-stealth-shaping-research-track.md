---
id: TODO-1010
title: Next-generation stealth shaping - research track from 2025 literature
severity: MEDIUM
phase: L
priority: P2
status: DONE
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
branches. The full ChameleonFlow reorder-window variant (redistribute
real packets across time instead of adding chaff) LANDED via TODO-1015 +
TODO-1016: bulk-classified datagrams get a gather-timer reorder window
with bounded adjacent swap (displacement <= 1, QUIC-safe); remaining
throughput lift is tracked as TODO-1017 (atomic pair emission).

ADAPTED - candidate 2 (Adaptive Tamaraw) partially:
`intelligent_policy.rs` now classifies traffic into `TrafficPhase`
(Dense/Sparse/BurstEdge on smoothed `ack_us`; the brain's EMA supplies the
hysteresis) and reads jitter scale from the phase table: dense 0.4, sparse
0.6 (external pacing), burst-edge 0.85. Before, the split was a flat
0.6/0.4 on `external_pacing` alone. The pairing is now coherent per phase -
dense traffic stays tight because the real stream masks itself, idle and
bursty phases get maximum jitter because burst edges carry the
fingerprint. Test `tamaraw_phase_table_scales_jitter_by_density` pins both
branches. The direction axis landed via **TODO-1019**: the phase table is
now evaluated per direction - `ack_us` (our emitted ACK delay tracks
inbound cadence) is the downstream row steering padding/chaff, while
`up_us` (brain-folds `delivery_rate` into a packet inter-arrival) is the
upstream row steering jitter/pacing; `up_us <= 0` keeps the symmetric
fallback until an upload estimate exists.

CLOSED (2026-09-21): every candidate has a written verdict and a home.
Candidate 4 stays deferred-by-verdict (QUICstep, see study below).
Candidate 5 landed as TODO-1014. ChameleonFlow reorder + 80% gate closed
via TODO-1015/1016/1017. Tamaraw direction split landed as TODO-1019.
This standing track has no remaining adopt/adapt work.

## Design studies (2026-09-20)

### Candidate 4 - QUICstep / CoMPS connection-migration splitting: STUDY

What the literature proposes: run the handshake (the SNI/ALPN-bearing,
fingerprint-heavy phase) over a cover path, then migrate the data phase to
a different path. The censor never sees the identifying phase on the data
path, and the cover channel carries only a few KB instead of the full flow.

Verified plumbing anchors:
- `PendingPathValidation` + path validation state machines exist in
  `src/transport/connection/lifecycle.rs`; migration/config knobs live in
  `src/transport/config.rs` (nat/migration flags) and
  `src/implementations/client/connection.rs`.
- Our handshake is already non-standard: no QUIC Initial packet format,
  so the Initial-decryption SNI-extraction the GFW performs on stock QUIC
  does not apply. The residual risk is correlation of the data phase to a
  known deployment endpoint, not handshake parsing.

Design outcome:
- The paper's win condition (hide the SNI-bearing handshake from the data
  path's censor) partially transfers: our handshake has no visible SNI to
  hide, but splitting still severs the timing/size correlation between the
  auth phase and the bulk phase at the observer's vantage point.
- Real cost: migration needs a second reachable endpoint (relay or
  multi-homed server); a migration within the same /24 is itself a
  detectable signal. Server-side would need dual-socket accept or a
  relay-aware path table - that is deployment topology, not plumbing.
- VERDICT: **defer** - the marginal gain over the current posture (custom
  handshake + residual-only GFW pressure) does not justify a relay
  topology requirement. Revisit if a concrete deployment scenario demands
  endpoint decoupling; the plumbing hooks above are the entry points.

### Candidate 5 - UPGen deployment-seeded wire-image diversity: STUDY

What the literature proposes: per-deployment protocol variants so traffic
classifies as "unknown benign encrypted" rather than matching a single
circumvention-protocol signature. One wire signature must not identify
every deployment.

Verified anchors (`src/qftls/private_protocol.rs`,
`src/transport/packet/private_selection.rs`):
- Per-connection variance exists today: packet-AEAD keys/epochs derive via
  HKDF from the authenticated transcript (exporter labels, key-phase
  epochs in `private_selection.rs`). Content entropy is already
  per-connection.
- Deployment-invariant shape today: `QFPA` magic, capsule type 0x41,
  protocol version 1, `KNOWN_FLAGS`, the Proposal/Selection/Confirmation
  message layout, `PRIVATE_TAG_LEN`, exporter salts - every deployment
  emits the same outer capsule structure. A censor with one deployment's
  capture can signature-match all of them.

Design outcome:
- Introduce a `PrivateProtocolShape` descriptor: a deployment seed
  (provisioned with the server config, shared with clients out-of-band)
  expands via HKDF into shape knobs - TLV field order in the Proposal,
  pad-to granule for control capsules, the AEAD-family preference list
  ordering, and the negotiation pacing pattern. Wire *semantics* stay
  fixed; wire *layout* permutes per deployment.
- Correctness constraint: both sides must derive the same shape, so the
  seed must be part of the provisioned credential material (like the QKey
  registry entries), never negotiated - negotiating the seed on the wire
  would reintroduce a fixed signature.
- Anti-goal respected: this does not touch the standard QUIC-compatible
  path; it only permutes the already-private capsule namespace.
- VERDICT: **adapt** - moderate surgery, real signature-diversity win.
  Spawned as TODO-1014.

### Candidate 1 remainder - ChameleonFlow bounded reorder window: STUDY

The density rule (padding halves under dense ACK-clocked traffic) already
captures the cheap half. The full variant redistributes real packets
across a small time window instead of buying chaff.

Verified anchors: `FlowShaper::apply_jitter`/`is_burst_edge` already
implement time-domain perturbation at burst edges; the emit funnel is the
packet-composed send path (`src/transport/connection/send.rs` ->
`src/core/connection/send.rs`), and TODO-1011's `DatagramClass::Bulk`
already marks the subset of traffic whose inner protocol tolerates
delay/reorder.

Design outcome:
- A reorder window is a bounded delay queue (W ~ 5-15 ms, k ~ 8 packets)
  in the send drain: hold bulk-classified datagrams, emit them in a
  seed-permuted order to break train-length/direction alternation
  fingerprints. Packet-number allocation happens at compose time, so
  reordering composed packets is wire-legal (send order need not equal
  PN order).
- Hard constraints discovered: ACK/control packets must bypass the window
  (they are latency-critical and reordering them breaks QUIC's own
  clocking); interaction with the io_uring multishot drain and the
  sendmmsg batch tail needs care so the window does not just move the
  burst signature one layer down.
- VERDICT: **adapt with constraint** - apply the window only to
  `DatagramClass::Bulk` entries (TCP-in-tunnel tolerates it; protected
  classes keep strict order). Spawned as TODO-1015; success metric =
  train-structure entropy gain at <= 2 ms median added latency on bulk
  packets.
