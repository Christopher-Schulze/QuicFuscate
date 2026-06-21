# TODO 56: Runtime-Owned Optimization Surface Audit

## Scope
- Public optimization and acceleration APIs under:
  - `src/optimize/*`
  - `src/transport/*`
  - `src/accelerate.rs`
  - related module re-exports in `src/lib.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Some public optimization APIs are not runtime-owned and currently have no real production call sites.
  - Evidence: `src/optimize/memory.rs:14` (`memcpy_non_temporal`), `src/optimize/string.rs:10` (`string_equals`)
- Public transport/optimization surfaces still expose compat/test owners as if they were canonical runtime features.
  - Evidence: `src/transport.rs:22`; `src/transport/xdp.rs:809`
- The repo still contains a broad optimization story that is larger than the current canonical runtime path.

## Objectives
- Classify every public optimization API by real ownership.
- Remove or quarantine orphan public performance surfaces.
- Keep only runtime-owned or explicitly test-only optimization entrypoints visible.

## Work Breakdown
### A. Inventory
- [x] Build a symbol-level inventory for public optimize/transport/accelerate exports.
- [x] Tag each symbol as `runtime-owned`, `compat-only`, `test-only`, or `orphan`.

### B. Orphan Surface Resolution
- [x] Resolve orphan APIs like custom memcpy/string-equality helpers.
- [x] Resolve any other public optimize symbols with no canonical runtime owner.

### C. Public API Cleanup
- [x] Reduce module re-exports that imply multiple competing optimization owners.
- [x] Keep explicit test-only boundaries for retained non-runtime helpers.

### D. Guardrails
- [x] Extend audit scripts to flag newly introduced orphan public optimization surfaces.
- [x] Add docs/runtime checks so optimization claims only cover runtime-owned features.

## Acceptance Criteria
- [x] Every public optimization API has a clear owner and status.
- [x] Orphan surfaces are removed, quarantined, or deliberately integrated.
- [x] Audit scripts detect future orphan optimization exports.

## Deliverables
- [x] Optimization surface ownership matrix.
- [x] Reduced public optimization API surface.
- [x] New guardrails for orphan performance helpers.

## Progress Notes
- 2026-03-05: Created from deep review of public performance surfaces after dead/shadow acceleration cleanup.
- 2026-03-06: Reclassified `optimize::transport::{bitmap_set_range,count_ecn_marks,decode_packet_number}` as parity/test-only surface and gated both the public entrypoints and their private SIMD backends behind `cfg(any(test, feature = "rust-tests"))`, leaving `aggregate_congestion(...)` as the runtime-owned transport acceleration entrypoint.
- 2026-03-06: Reclassified `optimize::memory::{memcpy_non_temporal,transpose_matrix,prefetch_sequential}` and `optimize::random::{random_u64,random_bytes_secure,shuffle}` as parity/test-oriented utility surface, then gated those public entrypoints and their private SIMD backends behind `cfg(any(test, feature = "rust-tests"))`.
- 2026-03-06: Reclassified `optimize::stealth::{generate_http_headers,add_tls_padding,generate_fake_hmac,shape_traffic_pattern}` as parity/test-only helpers and gated them behind `cfg(any(test, feature = "rust-tests"))`, leaving only the actual runtime-owned stealth acceleration surface visible in normal builds.
- 2026-03-08: Audited the trailing test/utility cluster in `src/optimize.rs` and found only `ConstPacketPool` to have an external rust-test owner through `scripts/tests/rust/rt-security-suite.rs`. Retained `ConstPacketPool` plus its `ConstBuffer` contract as explicit rust-test surface, kept `ConstRingBuffer` crate-internal, and removed the dead non-runtime tail helpers entirely:
  - `AlignedBuffer`
  - `LockFreePacketQueue`
  - `BoundedQueue`
  - `LockFreeStreamBuffer`
  - `LockFreeMemoryPool`
  - `AtomicStats`
- 2026-03-08: Validation after the optimize-tail collapse remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Removed the next orphan optimize utility exports with no external or runtime-owned callers:
  - `optimize::memory::memcpy_non_temporal(...)`
  - `optimize::memory::prefetch_sequential(...)`
  - `optimize::string::string_equals(...)`
- 2026-03-08: Removed the private SIMD/backend helpers that existed only for those orphan public entrypoints:
  - `memcpy_non_temporal_sse(...)`
  - `prefetch_sequential_x86(...)`
  - `string_equals_avx2(...)`
  - `string_equals_neon(...)`
  - `string_equals_sve2(...)`
  - `string_equals_sve2_impl(...)`
- 2026-03-08: Retained `optimize::memory::transpose_matrix(...)` because it still has a real external rust-test owner through `scripts/tests/rust/rt-transpose-parity.rs`.
- 2026-03-08: Validation after the orphan memory/string removal remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Audited the remaining `optimize::memory` utility exports and found only `LockFreeRingBuffer` to have an external rust-test owner through `scripts/tests/rust/rt-ring-buffer-parity.rs`.
- 2026-03-08: Removed the orphan memory utility exports with no runtime or external test owner:
  - `prefetch_random(...)`
  - `alloc_cache_aligned(...)`
  - `clear_cache_lines(...)`
  - `alloc_numa_local(...)`
- 2026-03-08: Removed the private backend helpers that existed only for those orphan memory entrypoints:
  - `prefetch_random_x86(...)`
  - `clear_cache_lines_x86(...)`
- 2026-03-08: Validation after the memory utility collapse remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Audited the open helper shell around `optimize::stealth::AsciiSimdBackend`.
- 2026-03-08: Kept `AsciiSimdBackend` and its instance methods as the real runtime-owned ASCII formatting surface used by `src/stealth.rs`.
- 2026-03-08: Removed the orphan wrapper surface with no runtime or external rust-test owner:
  - `append_ascii_simd(...)`
  - `append_decimal_simd(...)`
  - `append_lower_hex_simd(...)`
  - `titlecase_header_name(...)`
- 2026-03-08: Reduced the internal ASCII perf-smoke owner to unit-test-only by moving these items from `cfg(any(test, feature = "rust-tests"))` to `cfg(test)`:
  - `StealthAsciiBenchmarkScenario`
  - `STEALTH_ASCII_BENCHMARK_SET`
  - `StealthAsciiPerfThresholds`
  - `STEALTH_ASCII_INTERNAL_TARGETS`
  - `evaluate_stealth_ascii_perf_smoke(...)`
- 2026-03-08: Removed the now-dead lowercase helper tail after deleting `titlecase_header_name(...)`:
  - `lowercase_ascii_scalar(...)`
  - `lowercase_ascii_sse2(...)`
  - `lowercase_ascii_neon(...)`
- 2026-03-08: Validation after the stealth wrapper/perf-shell collapse remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Audited the retained `optimize::transport` surface again after earlier parity gating:
  - `aggregate_congestion(...)` remains the runtime-owned entrypoint
  - `bitmap_set_range(...)`, `count_ecn_marks(...)`, and `decode_packet_number(...)` remain explicit rust-test parity surface
- 2026-03-08: Removed the remaining orphan transport utility exports with no runtime or external rust-test owner:
  - `ack_range_search(...)`
  - `parse_stream_frames(...)`
- 2026-03-08: Removed the private backend and legacy test tail that existed only for those orphan transport entrypoints:
  - `ack_range_search_avx2(...)`
  - `ack_range_search_neon(...)`
  - `parse_stream_frames_scalar(...)`
  - `parse_stream_frames_neon(...)`
  - `parse_stream_frames_avx2(...)`
  - `read_varint(...)`
  - `tests_stream_neon`
- 2026-03-08: Validation after the orphan transport collapse remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Audited the remaining `optimize::brain` helper surface and confirmed the retained ownership split:
  - `decay_histogram(...)` and `jensen_shannon_divergence(...)` remain real runtime-owned SIMD math used by `src/brain.rs`
  - `moving_average(...)`, `compute_percentile(...)`, `relu_batch(...)`, and `softmax_batch(...)` remain explicit rust-test parity surface
- 2026-03-08: Removed the orphan docs-only `optimize::brain` helpers with no runtime or external rust-test owner:
  - `compute_statistics(...)`
  - `compute_correlation(...)`
  - `matrix_multiply(...)`
- 2026-03-08: Removed the backend-only implementation tails that existed only for those orphan `optimize::brain` entrypoints, including the matrix AMX/AVX/FMA/NEON/SVE paths and the statistics/correlation helper backends.
- 2026-03-08: Validation after the orphan brain-helper collapse remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Audited `optimize::sort` and confirmed there is no canonical runtime owner for its public surface:
  - `sort_u32(...)`
  - `sort_f32(...)`
  - `argsort(...)`
- 2026-03-08: Reduced `optimize::sort` to explicit parity/test-only surface by gating the module export in `src/optimize.rs` and the compatibility re-export in `src/accelerate.rs` behind `cfg(any(test, feature = "rust-tests"))`.
- 2026-03-08: Validation after the sort export-boundary collapse remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Audited the remaining public helper functions in `optimize::telemetry` and confirmed the retained ownership split:
  - `export_telemetry_text(...)`, `publish_cpu_profile_mask(...)`, `update_memory_usage(...)`, and `flush(...)` remain runtime-owned
  - `cpu_profile_mask(...)` remains retained for explicit test/runtime parity around CPU-profile publication
- 2026-03-08: Removed the orphan public helper `telemetry_snapshot_text(...)` because it had no runtime or external rust-test owner.
- 2026-03-08: Validation after the telemetry helper collapse remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Removed the remaining orphan public optimize helpers with no runtime or external rust-test owner:
  - `optimize::string::validate_utf8(...)`
  - `optimize::string::parse_u64(...)`
  - `optimize::stealth::mix_entropy(...)`
  - `optimize::stealth::generate_http_headers(...)`
  - `optimize::stealth::shape_traffic_pattern(...)`
- 2026-03-08: Removed the backend-only implementation tails that existed only for those orphan string/stealth entrypoints.
- 2026-03-08: Extended `scripts/tests/audits/audit-runtime-guardrails.sh` so removed orphan optimize exports cannot silently reappear as broad public surface.
- 2026-03-08: Validation after the final string/stealth + guardrail sweep remained green:
  - `cargo check`
  - `cargo clippy --all-targets --all-features -- -W clippy::all`
- 2026-03-08: Runtime guardrail audit also remained clean after the final TODO 56 closure:
  - `scripts/tests/audits/audit-runtime-guardrails.sh`
  - Critical: 0
  - Warnings: 0
