# TODO 43: Hot-Path Optimization and Fastpath Wiring (src-only)

## Scope
- Production hot-path optimization in `src/implementations/client/io_driver.rs`, `src/transport/*`, `src/interface.rs`, and `src/optimize.rs`.
- No UI modifications in `archive/apps/desktop/src/` or `archive/apps/web-admin-ui/src/`.

## Objectives
- Wire existing optimization infrastructure into the real production path.
- Eliminate no-op fastpath switches and runtime stubs on critical data paths.
- Ensure hardware detection translates to actual accelerated execution.
- Reduce copy/allocation overhead and maximize sustained throughput.

## Work Breakdown

### A. io_driver Production Path Upgrade
- [x] Replace copy-heavy send/recv loops with zero-copy aware buffer flow where possible.
- [x] Integrate batch send/recv strategy on supported platforms.
- [x] Remove avoidable temporary `Vec` allocations in steady-state loop.
- [x] Add regression tests for behavior parity after fastpath integration.

### B. Fastpath Runtime Wiring
- [x] Wire `QUICFUSCATE_FASTPATH` selection into actual runtime initialization.
- [x] Ensure selected fastpath materially changes transport behavior.
- [x] Remove or implement any no-op branches in fastpath switch logic.
- [x] Add tests that prove each fastpath selector is reachable and active.

### C. io_uring and Transport Integration
- [x] Implement real io_uring path where currently stubbed.
- [x] Provide robust fallback path with explicit telemetry when unavailable.
- [x] Integrate io_uring path into production loop, not only tests or helpers.
- [x] Add performance and correctness tests for io_uring vs fallback.

### D. TUN Write Path Completion
- [x] Replace TUN io_uring stub in `interface.rs` with real implementation or remove claim.
- [x] Ensure TUN fastpath and transport fastpath are operationally consistent.
- [x] Add tests for packet write/read correctness on fastpath and fallback.
- [x] Add telemetry counters for TUN path selection outcomes.

### E. Hardware Detection to Dispatch Consistency
- [x] Audit detection-to-dispatch mapping for all hot-path operations.
- [x] Ensure detected capabilities are consumed by runtime dispatch tables.
- [x] Remove dead capability branches or make them exercised.
- [x] Add tests that assert dispatch choice under simulated CPU feature sets.

### F. Performance Validation and Guardrails
- [x] Define benchmark set for steady-state throughput, p99 latency, and CPU cost.
- [x] Add CI-friendly smoke performance checks to catch severe regressions.
- [x] Add instrumentation for copy count / allocation pressure in hot path.
- [x] Produce pass/fail thresholds for optimization claims.

## Acceptance Criteria
- [x] Main client I/O path uses wired fastpath/zero-copy strategy where supported.
- [x] Fastpath configuration switches are functionally effective and tested.
- [x] io_uring and TUN fastpaths are real and measurable (or removed if unsupported).
- [x] CPU feature detection maps to live dispatch decisions in production.
- [x] Performance regressions are guarded by reproducible checks.

## Deliverables
- [x] Updated hot-path runtime modules in `src/`.
- [x] New tests/benchmarks and telemetry checks.
- [x] Updated tracking status in `docs/todo.md` and this file.

## Progress Notes
- 2026-02-23: Replaced the TUN io_uring write stub in `src/interface.rs` with a real `transport::uring::try_send_connected` fastpath attempt and explicit fallback semantics.
- 2026-02-23: Extended `TunDevice` with Unix raw-fd exposure hook and wired Linux/macOS implementations to expose device descriptors for fastpath integration.
- 2026-02-23: Wired client outbound UDP path in `src/implementations/client/io_driver.rs` to attempt io_uring fastpath send before async socket fallback.
- 2026-02-23: Runtime fastpath mode selection via `QUICFUSCATE_FASTPATH` is now enforced in `src/implementations/client/io_driver.rs` (`off/uring/xdp/auto`), with selector tests for parse/activation semantics.
- 2026-02-23: `src/transport/xdp.rs` now returns explicit `Unsupported` on unwired `enable_uring` instead of silent success, removing a no-op fastpath branch.
- 2026-02-23: Added TUN fastpath selection telemetry counters in `src/optimize/telemetry.rs` and wired updates in `src/interface.rs`.
- 2026-02-23: Removed steady-state temporary packet `Vec` allocations in `src/implementations/client/io_driver.rs` outbound/inbound loops by switching to slice-based send/write flow with lock-scoped extraction.
- 2026-02-23: Added outbound Linux batch send path in `src/implementations/client/io_driver.rs` using `optimize::zc_batch::sendmmsg` with fallback to existing uring/socket per-packet path.
- 2026-02-23: Added inbound receive batching in `src/implementations/client/io_driver.rs` by draining additional ready datagrams via `try_recv` into pre-allocated batch buffers per loop iteration.
- 2026-02-23: Unified fastpath mode parsing across TUN and client transport paths by introducing shared `FastpathMode` in `src/interface.rs` and reusing it from `src/implementations/client/io_driver.rs`.
- 2026-02-23: Added io_driver regression coverage for fastpath mode selection and normalized batch-size bounds in `src/implementations/client/io_driver.rs` tests.
- 2026-02-23: Wired `FastPathTransport::enable_uring()` in `src/transport/xdp.rs` to construct and activate a real `uring_udp::UringUdp` transport (queue depth/buffer registration from env) instead of returning `Unsupported`.
- 2026-02-23: Added Linux+`uring_sys` regression coverage in `src/transport/xdp.rs` to assert `enable_uring()` no longer returns the historical unwired-stub error path.
- 2026-02-23: Added runtime CPU profile mask publication in `src/implementations/client/io_driver.rs` via `optimize::telemetry::publish_cpu_profile_mask(...)`, plus deterministic profile-mask mapping tests in `src/optimize/telemetry.rs` to assert simulated dispatch-feature choices.
- 2026-02-23: Added hotpath pressure instrumentation in `src/optimize/telemetry.rs` and wired counters in `src/implementations/client/io_driver.rs` (`IO_DRIVER_COPY_OPS`, `IO_DRIVER_COPY_BYTES`, `IO_DRIVER_BATCH_DRAIN_PACKETS`, `IO_DRIVER_SENDMMSG_CALLS`, `IO_DRIVER_SENDMMSG_PACKETS`).
- 2026-02-23: Added full `CpuProfile` branch-coverage assertion in `src/optimize/telemetry.rs` (`cpu_profile_mask_covers_all_profiles`) so every profile path in mask publication logic is exercised.
- 2026-02-23: Added deterministic TUN read/write correctness coverage in `src/interface.rs` (`read_block_returns_packet_payload`, `write_packet_direct_fallback_returns_device_length`) and Linux uring fallback telemetry-path assertion (`write_packet_uring_fallback_increments_telemetry_when_fd_missing`).
- 2026-02-23: Added explicit outbound dispatch mapping in `src/implementations/client/io_driver.rs` (`resolve_outbound_dispatch`) with correctness tests for `uring/sendmmsg/socket` selection and runtime usage in production send loop.
- 2026-02-23: Added CPU-profile-aware dispatch shaping in `src/implementations/client/io_driver.rs` (`profile_prefers_wide_batches`) so detected capabilities now drive live batch-size dispatch caps.
- 2026-02-23: Added CI-friendly deterministic hotpath perf smoke guard (`evaluate_hotpath_perf_smoke`) with explicit pass/fail thresholds (`HotpathPerfThresholds`) and regression tests, plus a concrete benchmark scenario set (`HOTPATH_BENCHMARK_SET`) for throughput/latency/CPU validation runs.
- 2026-02-23: Final warning-cleanup pass completed for cross-target builds (`io_driver` Linux-gated dispatch symbols/fields); follow-up validation run `cargo test --test stealth_mode_matrix --test masque_runtime_integration` completed without compiler warnings.
- 2026-02-24: Rewired dormant XDP telemetry paths in `src/optimize.rs` so runtime now updates `XDP_ACTIVE` and `XDP_FALLBACKS` through manager initialization, socket creation fallback, Linux XDP reconfigure/send/recv fallback transitions, and Unix UDP fallback construction.
- 2026-02-24: Extended text telemetry export in `src/optimize/telemetry.rs` with live gauges `quicfuscate_xdp_active` and `quicfuscate_simd_active` to make fastpath/acceleration state externally observable in runtime dumps.
