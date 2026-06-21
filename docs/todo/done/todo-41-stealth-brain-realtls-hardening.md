# TODO 41: Stealth + Brain + RealTLS/CHLO Hardening (src-only)

## Scope
- Runtime-only hardening of `src/stealth.rs`, `src/brain.rs`, `src/core.rs`, `src/qftls.rs`, and related transport glue.
- No UI modifications in `archive/apps/desktop/src/` or `archive/apps/web-admin-ui/src/`.

## Objectives
- Remove compile blockers and unresolved feature-paths.
- Replace placeholder tunnel logic with real end-to-end transport behavior.
- Make Intelligent mode truly continuous and situational, not probe-only.
- Validate RealTLS/CHLO realism, mode coherence, and profile-level behavior.
- Ensure all relevant Stealth paths use available hardware acceleration.

## Work Breakdown

### A. Compile Integrity and Feature Wiring
- [x] Implement and wire `DeepIntegrationOrchestrator` for `orchestrator` feature paths.
- [x] Ensure orchestrator paths compile under feature permutations used in CI.
- [x] Remove or replace any dead orchestrator references if no runtime use remains.
- [x] Add regression tests for orchestrator build and runtime activation.

### B. MASQUE and Cover Traffic Real Data Path
- [x] Replace MASQUE placeholder logic with real CONNECT-UDP tunnel establishment.
- [x] Implement actual payload forwarding through MASQUE tunnel path.
- [x] Wire cover-traffic scheduler outputs into a real egress mechanism.
- [x] Add failure handling and fallback behavior when MASQUE fails.
- [x] Add integration tests for tunnel setup, data flow, and fallback.

### C. Intelligent Mode Sophistication
- [x] Extend Intelligent mode from probe-only escalation to continuous multi-signal control.
- [x] Introduce explicit control inputs: loss, RTT jitter, timeout pressure, retransmit pressure, probe signals.
- [x] Implement smooth transitions between stealth levels with anti-flapping hysteresis.
- [x] Add deterministic tests for transition stability and non-regressive behavior.
- [x] Add telemetry counters for transitions and escalation reasons.

### D. Stealth Mode Coherence and Conflict Elimination
- [x] Produce a mode-feature matrix in code tests and verify each mode activates intended features.
- [x] Detect and eliminate feature conflicts (for example timing obfuscation vs pacing constraints).
- [x] Ensure Anti-DPI escalation stack is strictly cumulative and reversible.
- [x] Add assertions/tests that no mode silently disables required stealth primitives.

### E. RealTLS/CHLO Fidelity
- [x] Validate TLS/CHLO synthesis paths against current profile semantics.
- [x] Ensure profile-driven ClientHello behavior is deterministic and configurable.
- [x] Close any mismatches between advertised mode and emitted TLS behaviors.
- [x] Add protocol-level tests for CHLO/TLS profile selection and output constraints.

### F. Hardware Acceleration Coverage (Stealth Context)
- [x] Audit all stealth hot paths for SIMD/HW dispatch usage.
- [x] Wire missing acceleration paths where infrastructure exists.
- [x] Add telemetry validation for accelerated vs scalar fallback execution.
- [x] Add benchmark hooks for representative stealth-heavy workloads.

## Acceptance Criteria
- [x] `orchestrator` feature path compiles and is runtime-tested.
- [x] MASQUE path moves real data and passes integration tests.
- [x] Intelligent mode demonstrates smooth, multi-signal adaptation in tests.
- [x] Stealth modes are conflict-free and deterministically validated.
- [x] RealTLS/CHLO profile behavior is tested and aligned to runtime policies.
- [x] Stealth acceleration coverage is measurable and verified by telemetry/tests.

## Deliverables
- [x] Updated runtime modules in `src/` with no placeholder critical path.
- [x] New/updated tests under existing Rust test structure.
- [x] Updated tracking entries in `docs/todo.md` and this file.

## Progress Notes
- 2026-02-23: Implemented `DeepIntegrationOrchestrator` in `src/brain.rs` and wired runtime signal updates from `src/core.rs` Intelligent loop paths.
- 2026-02-23: Updated orchestrator feature tests to use the live orchestrator API instead of missing-field access.
- 2026-02-23: Hardened `MasqueManager` path handling and capsule bounds checks in `src/stealth.rs`; replaced no-op async tunnel/data routines with real outbound CONNECT/POST request attempts plus explicit failure logging.
- 2026-02-23: Added persistent MASQUE tunnel state in `src/core.rs` and implemented real payload forwarding via `send_masque_datagram` (including fallback behavior in HTTP/3 body path).
- 2026-02-23: Added orchestrator feature/runtime integration regression coverage in `scripts/tests/rust/integration/orchestrator_runtime_activation.rs` (feature-enabled activation/signal flow and feature-disabled compile guard).
- 2026-02-23: Added deterministic Stealth mode matrix and anti-DPI cumulative/reversible behavior tests in `scripts/tests/rust/integration/stealth_mode_matrix.rs`, including required-primitive assertions.
- 2026-02-23: Added strict stealth config conflict guards in `src/stealth.rs::validate` (server-push/http3 dependency, choke target requirement, performance-mode anti-conflict policy) with regression tests in `scripts/tests/rust/integration/stealth_mode_matrix.rs`.
- 2026-02-23: Extended RealTLS profile validation in `src/qftls.rs` tests with deterministic fingerprint->profile mapping, browser-semantic mapping checks, policy constraints (ALPN/ChaCha filtering), and CHLO extension-order constraints.
- 2026-02-23: Completed Intelligent multi-signal runtime wiring end-to-end: `src/brain.rs` now drives stable level-hint hysteresis with explicit reason counters and deterministic hysteresis tests; `src/stealth.rs` consumes brain level hints for MASQUE and runtime server-push gating; `src/core.rs` continuously synchronizes intelligent level into request/poll loops, including de-escalation shutdown and level-aware orchestrator intensity.
- 2026-02-23: Added MASQUE integration regression coverage in `scripts/tests/rust/integration/masque_runtime_integration.rs` for target validation, tunnel lifecycle stats, data-path capsule parsing, and missing-tunnel fallback behavior.
- 2026-02-23: Added stealth ASCII acceleration telemetry counters (AVX2/SSE2/NEON/scalar byte totals) exported via `src/optimize/telemetry.rs`; wired accounting in `src/optimize/stealth.rs` dispatch paths; added deterministic benchmark hooks (`STEALTH_ASCII_BENCHMARK_SET`, smoke-threshold evaluation) with unit tests.
- 2026-02-23: Completed stealth acceleration audit/wiring for ASCII-heavy hot paths: hardware-dispatch accounting is now explicit at each backend branch and scalar fallback now uses `simd::core::memcpy_fast` instead of plain `extend_from_slice`, keeping fallback path aligned with available optimized memory-copy infrastructure.
- 2026-02-23: Verified runtime coverage with targeted test runs: `cargo test --test stealth_mode_matrix --test masque_runtime_integration`, `cargo test --lib intelligent_hysteresis`, `cargo test --lib stealth_ascii_perf_smoke_thresholds_pass_and_fail`, and `cargo test --lib stealth_ascii_benchmark_set_is_non_empty_and_unique` all passed.
- 2026-02-24: Completed Server-Push observability hardening: `src/core.rs` now passes non-zero burst-byte estimates into `update_server_push_state`, `src/stealth.rs` tracks a 60s burst window and trigger-reason semantics (`time/loss/gating`), and `src/optimize/telemetry.rs` exports bursts-total, bursts-last-minute, total-cover-bytes, intensity gauge, and reason counters.
- 2026-02-24: Added deterministic mode-level `should_trigger_server_push()` coverage in `scripts/tests/rust/integration/stealth_mode_matrix.rs` (Off/Performance/Stealth/AntiDPI/Intelligent) and expanded orchestrator integration coverage in `scripts/tests/rust/integration/orchestrator_runtime_activation.rs` with loss/cpu/memory/bandwidth trigger matrix assertions.
- 2026-02-23: Implemented server-push runtime observability and reason tracking: `src/stealth.rs` now records sliding-window burst cadence and accepts explicit trigger reasons (`Time/Loss/Gating`), while `src/core.rs` computes cover-byte estimates per burst and forwards reasoned updates instead of zero-byte placeholders.
- 2026-02-23: Added exported server-push telemetry in `src/optimize/telemetry.rs` (`server_push_bursts_total`, `server_push_total_cover_bytes`, `server_push_bursts_last_minute`, `server_push_current_intensity_ppm`, reason counters for loss/time/gating).
- 2026-02-23: Added deterministic mode-matrix server-push trigger coverage in `scripts/tests/rust/integration/stealth_mode_matrix.rs` and extended orchestrator integration coverage in `scripts/tests/rust/integration/orchestrator_runtime_activation.rs` to validate trigger behavior under Loss/CPU/Mem/BW signal combinations.
- 2026-02-24: Wired runtime TLS CH override execution into live transport loops: `src/core.rs` now calls `Connection::do_tls_handshake(...)` on both send and recv paths using optional env template `QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE`, so RealTLS CH override path is no longer passive-only.
