# TODO 42: FEC Runtime Adaptation and Extreme-Loss Resilience (src-only)

## Scope
- Runtime wiring and algorithmic hardening for `src/fec.rs`, `src/core.rs`, `src/transport/recovery.rs`, and related observers.
- No UI modifications in `archive/apps/desktop/src/` or `archive/apps/web-admin-ui/src/`.

## Objectives
- Ensure adaptive FEC is truly always-on intelligent in live runtime.
- Wire loss feedback from real transport/recovery events.
- Activate and validate SIMD/FEC acceleration consistently.
- Guarantee stable behavior under extreme packet-loss scenarios.

## Work Breakdown

### A. Real Loss Feedback Wiring
- [x] Wire transport/recovery loss metrics into `AdaptiveFec::report_loss`.
- [x] Ensure callbacks are invoked on live packet-loss and recovery events.
- [x] Validate end-to-end mode transitions from real network conditions.
- [x] Add integration tests with synthetic and replayed loss traces.

### B. Adaptive Mode Logic Stabilization
- [x] Enforce clear hysteresis and anti-flap behavior across all FEC modes.
- [x] Validate transition safety for Zero/Light/Normal/Strong/Extreme/Fountain/Streaming.
- [x] Add deterministic transition tests for boundary thresholds.
- [x] Expose transition reason telemetry for observability.

### C. Extreme-Loss Robustness
- [x] Validate and tune behavior for very high loss rates and burst-loss patterns.
- [x] Ensure fallback/escalation paths preserve session continuity where feasible.
- [x] Add stress scenarios for prolonged high-loss, reorder, and jitter combinations.
- [x] Add soak tests for long-running instability detection.

### D. Callback and Observer Integration
- [x] Activate existing FEC callback hooks in runtime recovery loop.
- [x] Integrate observer outputs into adaptive controls consistently.
- [x] Remove dead callback branches or make them active and tested.
- [x] Add regression tests for callback invocation ordering and semantics.

### E. SIMD and Hardware Path Activation
- [x] Ensure FEC SIMD activation is called in production initialization paths.
- [x] Validate dispatch behavior across scalar/AVX/NEON/SVE where applicable.
- [x] Add telemetry assertions to prove accelerated path use.
- [x] Add benchmarks for encode/decode throughput and CPU efficiency.

### F. Efficiency and Memory Discipline
- [x] Audit allocations in FEC hot paths and remove avoidable per-packet allocations.
- [x] Validate ring/buffer reuse strategy under high load.
- [x] Tune repair emission cadence for performance vs resilience balance.
- [x] Add performance guard tests to detect regressions.

## Acceptance Criteria
- [x] Live runtime triggers `report_loss` from real transport signals.
- [x] Mode switching is deterministic, stable, and anti-flap tested.
- [x] Extreme-loss scenarios maintain target stability behavior.
- [x] FEC callbacks/observers are active and covered by tests.
- [x] SIMD paths are consistently activated where available and telemetry-proven.
- [x] Throughput/latency/CPU metrics meet defined internal targets.

## Deliverables
- [x] Updated FEC runtime wiring in `src/`.
- [x] New/updated unit/integration/stress tests.
- [x] Updated tracking state in `docs/todo.md` and this file.

## Progress Notes
- 2026-02-23: Wired live transport loss deltas in `src/core.rs` into `AdaptiveFec::report_loss` (delta-based, runtime path).
- 2026-02-23: Enabled `AdaptiveFec::enable_simd_acceleration()` during `QuicFuscateConnection` initialization to avoid dormant SIMD codepaths.
- 2026-02-23: Orchestrator resource inputs now receive live process CPU/memory estimates from `src/core.rs` periodic telemetry update path.
- 2026-02-23: Added recovery-driven FEC callback plumbing in `src/transport/recovery.rs` and `src/transport/connection.rs`, including packet-threshold loss inference and callback-feedback counters consumed in `src/core.rs`.
- 2026-02-23: Hardened adaptive mode switching in `src/fec.rs` with explicit hysteresis, directional dwell intervals, and stable-target gating to reduce mode flapping.
- 2026-02-23: Fixed adaptive mode derivation bug in `src/fec.rs` where mode-manager switch output could keep stale mode selection; update path now uses manager post-update state/window consistently.
- 2026-02-23: Added FEC switch-reason telemetry counters and text export in `src/optimize/telemetry.rs` (`adaptive`, `force_on`, `extreme`, `disturbance`).
- 2026-02-23: Added deterministic FEC adaptation tests in `src/fec.rs` covering anti-flap downshift guard, boundary progression, and extreme-loss reason telemetry increment.
- 2026-02-23: Added recovery callback regression coverage in `src/transport/recovery.rs` validating sent/loss callback metadata semantics (`packet_num`, bytes) and legacy `on_loss()` compatibility behavior.
- 2026-02-23: Added prolonged high-loss stability coverage in `src/fec.rs` (`test_prolonged_extreme_loss_stays_in_high_resilience_mode`) to verify convergence to and retention of Fountain mode under sustained extreme loss.
- 2026-02-23: Added SIMD activation telemetry assertion coverage in `src/fec.rs` (`test_enable_simd_acceleration_updates_telemetry`) to verify runtime SIMD selection is observable through telemetry counters.
- 2026-02-23: Added deterministic bursty-loss/jitter and long-running mixed-loss trace coverage in `src/fec.rs` (`test_bursty_jitter_trace_remains_in_resilient_modes`, `test_long_running_mixed_loss_trace_stays_operational`) to harden stress/soak adaptation confidence.
- 2026-02-23: Added replay-style end-to-end adaptation trace coverage in `src/fec.rs` (`test_replayed_loss_trace_drives_end_to_end_adaptation`) and all-start-mode transition safety coverage (`test_transition_safety_for_all_start_modes_under_replay_trace`) including Streaming via `force_streaming_mode()`.
- 2026-02-23: Added explicit SIMD dispatch selection helper in `src/fec.rs` (`select_simd_level_from_features`) with deterministic scalar/AVX/NEON/SVE2 coverage test and SVE2 telemetry reporting path.
- 2026-02-23: Added FEC perf guardrails and benchmark scenario set in `src/fec.rs` (`FEC_BENCHMARK_SET`, `FecPerfThresholds`, `evaluate_fec_perf_smoke`) with deterministic pass/fail regression tests.
- 2026-02-23: Tuned dynamic repair cadence in `src/fec.rs` (`update_stream_interval`) to use explicit loss/disturbance targets and stepwise convergence, with deterministic high-loss/low-loss cadence tests.
- 2026-02-23: Eliminated per-send transient streaming repair queue allocation in `src/fec.rs` by introducing reusable `stream_repair_scratch` buffer, and added deterministic reuse coverage (`test_streaming_repair_scratch_queue_reused_under_load`).
- 2026-02-23: Added LazyDecoder pending-repair ring reuse validation under sustained load (`test_lazy_decoder_pending_repair_ring_reuse_under_load`) to enforce bounded queue behavior and capacity reuse.
- 2026-02-23: Promoted internal FEC performance targets to explicit constant (`FEC_INTERNAL_TARGETS`) and aligned perf-smoke checks/tests to assert throughput/latency/CPU guard compliance deterministically.
- 2026-02-24: Hardened forced streaming transition semantics in `src/fec.rs`: `force_streaming_mode()` now triggers real transition wiring (`transition_to_mode` + `mode_manager.force_state`) and updates FEC mode/window telemetry, eliminating the previous mode-only shortcut that could leave encoder/decoder state stale.
- 2026-02-24: Closed SIMD activation observability gap by driving `telemetry::SIMD_ACTIVE` directly from `AdaptiveFec::enable_simd_acceleration()` based on the selected runtime SIMD level.
