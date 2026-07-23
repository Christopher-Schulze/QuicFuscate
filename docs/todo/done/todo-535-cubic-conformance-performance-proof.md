---
id: TODO-535
title: Prove CUBIC conformance, fairness, and loss performance
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-22
depends_on: [TODO-452]
---

# TODO-535: Prove CUBIC Conformance, Fairness, and Loss Performance

## Why

CUBIC is selected through config, integrated into recovery and stealth shaping, and covered by algorithm-path units. Independent RFC vectors, the required K precision and memory bound, Reno coexistence, and real loss performance remain unproven.

## Acceptance

- Verify the implementation against current RFC 9438 and RFC 9406 requirements and independent published vectors; correct any algorithmic mismatch in production code.
- Prove cubic window and K calculations with less than 1e-6 relative error across boundary and large-window cases.
- Assert CUBIC controller memory overhead over Reno remains below 200 bytes on supported architectures.
- On a controlled shared bottleneck, prove CUBIC plus Reno Jain fairness above 0.8 without starvation.
- Under controlled 5% random loss, prove CUBIC throughput remains above 50% of its loss-free baseline and report comparison methodology.
- Retain explicit paced CUBIC as the canonical QuicFuscate contract and prove stealth wrapping plus all other CC regressions.
- Pass local Rust gates, native CI, Omega network proof, documentation/MAP/TODO truth, and preserve protected UI files.

## Sub-Tasks

- [x] Reconcile implementation math and HyStart behavior with primary RFC sources.
- [x] Add independent precision, conformance, size, and regression tests.
- [x] Build controlled fairness and loss experiments.
- [x] Execute local, native, and Omega evidence.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Created from TODO-452 reconciliation. Returning no pacing rate is superseded by the canonical recovery pacing contract.
- Primary-source audit found that the current K calculation assumes `cwnd_epoch = beta * W_max` instead of using the actual congestion-avoidance entry window required by RFC 9438. Congestion avoidance evaluates `W_cubic(t)` instead of the bounded `W_cubic(t + RTT)` target and replaces per-ACK `W_est` state with a time-derived approximation.
- The existing 8% RTT trigger is not HyStart++: RFC 9406 requires round minima, at least eight RTT samples, a 4-16 ms bounded threshold, Conservative Slow Start growth at one quarter rate, spurious-exit recovery, and five CSS rounds before congestion avoidance.
- CUBIC is wired into the low-level transport enum but absent from the engine configuration enum, CLI value enum, client/engine conversion, and server TOML override. The generic stealth wrapper preserves CUBIC dispatch but does not currently apply its jitter or dampening to CUBIC's explicit pacing rate.
- The implementation currently applies the multiplicative decrease once per lost packet. TODO-535 must collapse packets from one QUIC recovery episode into one congestion event and keep application-limited idle time out of the cubic epoch.
- The production controller now uses the RFC 9438 epoch K, bounded `W_cubic(t + RTT)` target, stateful Reno-friendly estimate, one reduction per recovery episode, and application-limited epoch suspension. HyStart++ now tracks rounds, eight-sample minima, the 4-16 ms threshold, Conservative Slow Start quarter growth, spurious recovery, and the five-round exit.
- Runtime selection now accepts CUBIC through engine config, client/server mapping, TOML override, and CLI. Stealth CUBIC retains explicit pacing while applying bounded jitter and optional two-percent dampening.
- The first clean local rebuild exposed concurrent removal of the repository `target/` directory, not a source failure. TODO-535 uses isolated `CARGO_TARGET_DIR=/tmp/quicfuscate-todo535-target` for reproducible gates.
- The shared-bottleneck audit found that Reno also reduced once per lost packet. Recovery-episode tracking is now consistent across Reno and CUBIC so a multi-packet QUIC loss event cannot repeatedly collapse either congestion window and invalidate coexistence measurements.
- Omega uses iproute2 6.1.0, whose netem interface provides `loss random PERCENT` without an explicit seed option. The live loss gate therefore uses three retained 5% random-loss trials and a median comparison instead of claiming unavailable seed determinism.
- Deterministic shared drop-tail evidence records CUBIC `13,389,600` bytes, Reno `14,367,600` bytes, and Jain fairness `0.998760`.
- Exact Omega run06 uses build-source archive SHA-256 `df1aed74696ed45ca1bb66e06556cf39b8298620fc60878570427dbcda4d0837`, compile-input digest `423cb07e9b4f64c3605ba28034257edcfb4124a4e5ccd86850908d6c5109a680`, and native AArch64 binary SHA-256 `2dc42fd87b77f50eaef96c0244a15adf8126f19d4593c5497f26acdb048483eb`. The 2 Mbit/s shared bottleneck records CUBIC 0.961 Mbit/s, Reno 0.951 Mbit/s, and Jain fairness `0.999974`. Three clean and three 5% random-loss CUBIC trials on a 5 Mbit/s bottleneck record 3.001 Mbit/s versus 2.862 Mbit/s median throughput, retaining 95.38%.
- `cargo test --features rust-tests` and `cargo clippy --all-targets --all-features -- -D warnings` pass locally and on native AArch64. Formatting, shell syntax, ShellCheck, task audit, documentation truth, diff integrity, and cleanup gates pass. Omega evidence remains at `/home/ubuntu/SOFTWARE/QuicFuscate/target/todo535/evidence/run06` with no product process, namespace, or qdisc residue.

## Deviations

None.
