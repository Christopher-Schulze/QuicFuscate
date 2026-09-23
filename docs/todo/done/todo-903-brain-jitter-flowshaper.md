---
id: TODO-903
title: Brain jitter gate and FlowShaper tuning
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-08-21
depends_on: []
---

# TODO-903: Brain Jitter Gate and FlowShaper Tuning

## Objective
Fix `src/transport/connection/send.rs:206-227` jitter gate hitting ALL packets inc ACK-only, and `stealth/manager.rs:649-653` uniform [1500,3000]us delay per datagram.

## Verified Evidence
- `send.rs:206-227` `TimingGate` applied to every packet.
- `manager.rs:649-653` `FlowShaper` uniform delay.
- `brain.rs:606` EnvSnapshot per ACK already covered by TODO-894.

## Acceptance
- Jitter only on data packets, not ACK-only. DONE: transport jitter was already
  gated on `SendInfo.congestion_controlled` (RFC 9002 sec. 7.2: identical
  partition to ack-eliciting). The remaining gap was the FlowShaper path -
  `StealthManager::process_outgoing_packet` saw only payload bytes and jittered
  every datagram. It now takes an explicit `ack_only` classification from the
  send path (`!send_info.congestion_controlled` at both call sites in
  `core/connection/send.rs`), skips FlowShaper jitter for pure ACK datagrams,
  still records them into shaper history as `StealthPacketClass::Ack` (they
  occupy the wire, so they feed the rate estimator), and keeps the explicit
  realtime choke applied - a configured bandwidth cap must hold for every byte.
- FlowShaper uses adaptive delay based on CE ratio, not uniform. DONE (see
  Deviations - history-derived traffic state instead of cross-crate CE wiring).
- `scripts/tests/suites/test-performance-regression.sh --only latency`
  unchanged. VERIFIED 2026-09-19: `--only latency --fast` PASS,
  `connection_1rtt_send_recv/payload_1024B` 8.68us / 223.5 MiB/s.

## Out of Scope
- No probe detection change.

## Deviations
- The original acceptance wording implied the shaper would consume the Brain's CE-ratio signal. Implementation instead derives traffic state from FlowShaper's own bounded packet history (2s window, already recorded via `record_and_prune`): bursty >=32 records -> low half of range, idle <8 -> full spread, steady -> classic uniform. Rationale: (1) FlowShaper lives in `qf-stealth` with no Brain dependency; wiring CE ratio across crate boundaries for a timing heuristic would couple stealth shaping to transport loss state and change the wire-visible delay profile under congestion - exactly when Anti-DPI cover matters most. (2) History-based rate is a direct proxy for burst/idle without new locks or cross-crate plumbing. Stealth-shape justification for "bursts stay tight": real client flows alternate tight bursts and long gaps; the previous flat uniform delay smoothed bursts into an unnatural constant-ish profile that is itself a fingerprint. Tests: `flow_shaper_burst_tightens_range`, `flow_shaper_idle_spreads_full_range`, plus seeded steady-band updates to the three existing tests (`src/stealth/tests.rs`, `src/stealth/manager/coverage_tests.rs`). qf-stealth 127/127, root flow_shaper 12/12.
