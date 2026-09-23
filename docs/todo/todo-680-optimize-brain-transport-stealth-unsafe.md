---
id: TODO-680
title: Audit unsafe blocks in optimize/brain, optimize/transport, optimize/stealth, and related hot paths
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-08-01
depends_on: []
---

# TODO-680: Audit Unsafe Blocks in `optimize/brain.rs`, `optimize/transport.rs`, `optimize/stealth.rs`, and Related Hot Paths

## Current execution gate (2026-09-23)

The findings and line numbers below are the historical audit baseline. The
listed local fixes have been implemented; TODO-834, TODO-836, TODO-837,
TODO-839, and TODO-689 are completed task owners. Current Optimize source is
under `src/optimize/`, while extracted SIMD implementations and former
`src/optimize/x86_sse2.rs` ownership are under `crates/qf-simd/src/`.
TODO-680 is OPEN for a fresh local dispatched-path/feature-predicate
inventory and available local checks. Closure still requires the unrun native
x86 BMI2/AVX10/VNNI, ARM SVE2, Linux UDP, sanitizer, and Miri proof for retained
paths. Before any native run, inventory the exact current dispatched functions,
their `target_feature` and runtime predicates, and select executable hosts
with those features. A test that returns early for an unavailable ISA is a
SKIP, never a pass. Run the existing parity/negative fixtures on the actual
ISA, retain source revision, CPU feature record, command, result, and artifact
path, and create a separate concrete defect task if a current path fails.
Do not reimplement the resolved historical findings or treat old line numbers
as current source anchors. Close only when every retained native lane has
evidence or a documented, justified removal from the supported surface.

## Why

The `optimize/` module uses `unsafe` for histogram decay, divergence computation, transport acceleration, and stealth scoring. Many of these paths use `*_arch` intrinsics and raw pointer arithmetic. Several were already implicated in the AVX-512 illegal-instruction bug on Windows (see TODO-519 history).

## Affected Files

- `src/optimize/brain.rs` (76 textual `unsafe` matches; SIMD and conversion helpers are in scope)
- `src/optimize/transport.rs` (32 textual `unsafe` matches; congestion, bitmap, ECN, and packet-number paths are in scope)
- `src/optimize/stealth.rs` (24 textual `unsafe` matches; ASCII, pattern, and padding paths are in scope)
- `src/optimize/iter.rs` (33 textual `unsafe` matches; reduction dispatch and vector tails are in scope)
- `src/optimize/string.rs` (25 textual `unsafe` matches; search and test-only base64 paths are in scope)
- `src/optimize/sort.rs` (9 textual `unsafe` matches; typed casts and small SIMD sorts are in scope)
- `src/optimize/compress.rs` (8 textual `unsafe` matches; byte compression vector tails are in scope)
- `src/optimize/udp.rs` (12 textual `unsafe` matches; Linux syscalls, sockaddr conversion, and test-only RPS are in scope)
- `src/optimize/telemetry.rs` (11 textual matches, but the current matches are documentation text rather than unsafe operations)
- `src/optimize/x86_sse2.rs` (2 public unsafe helpers; adjacent safety-documentation and caller proof are owned by TODO-836/TODO-689)

## Detailed Unsafe-Site Inventory

The original line inventory was a textual `rg unsafe` inventory, not an inventory of executable unsafe operations. The complete audit read every current source file listed above and classified each match as intrinsic, raw-pointer, FFI, test-only, documentation-only, or a cross-owner boundary.

| File | Current source boundary | Audit result |
|------|-------------------------|--------------|
| `brain.rs` | Histogram decay, Jensen-Shannon divergence, moving average, percentile, activation, and softmax SIMD helpers | Vector windows and tails are guarded for valid slice contracts. Current moving-average routing uses exact AVX512F/AVX2/SSE2 checks; native AVX10 profile proof and percentile input validation remain incomplete. |
| `transport.rs` | Congestion aggregation, bitmap range, ECN popcount, packet-number decode | Vector bounds are guarded. The public dispatcher now gates BMI2 explicitly; BMI2 range arithmetic does not fail closed for reversed or clipped ranges; packet-number length is not validated at the public helper; VNNI truncates inputs to 64 while the public helper does not state that bound. |
| `stealth.rs` | ASCII append, pattern injection, TLS padding | Normal vector tails are guarded. The SSE2 short-pattern branch stores a full 16-byte block for a shorter pattern, and adversarial position arithmetic can wrap before raw access. |
| `iter.rs` | `sum_f32`, `sum_u32`, and `sum_u64` plus architecture-specific reductions | Vector tails are guarded. The current dispatch uses exact AVX512F/AVX2/SSE2 features rather than the P1f profile enum; native feature-limited P1f proof remains open. |
| `string.rs` | String search and test/rust-tests base64 helpers | Normal x86 tails are guarded. The SVE2 encoder's output expansion exceeds one vector-length output predicate and leaves unwritten trailing bytes; TODO-834 corrected the string-search feature intersections and stale SVE2 symbol. |
| `sort.rs` | Small x86/NEON sort helpers and `TypeId`-based typed casts | Slice lengths and fixed local arrays are bounded. The `TypeId` cast relies on exact type equality and needs formal safety documentation, not a newly proven memory defect. |
| `compress.rs` | Scalar, x86, and NEON byte compression | Vector loads/stores and tails are guarded for valid slices. The dispatch and test matrix do not prove every profile intersection; no active pointer OOB was established in this pass. |
| `udp.rs` | Linux `sendmmsg`/`recvmmsg`, sockaddr construction, macOS `sendmsg_x`, test-only RPS | Stable vector storage and negative syscall returns are present. Receive `msg_len` values are discarded, partial `sockaddr_storage` initialization is converted with `assume_init`, syscall count casts are unchecked, and test-only RPS shifts panic at 128 CPUs and writes a path derived from an unvalidated interface name. |
| `telemetry.rs` | Metrics, atomics, and `OnceLock` | The current `unsafe` matches are prose about unsafe memory pools, not executable unsafe operations. This is a stale inventory false positive owned by TODO-689. |
| `x86_sse2.rs` | Two public SSE2 XOR helpers | Width and tail guards are present. Function-level safety documentation is missing and the adjacent proof remains under TODO-836/TODO-689. |

## Findings

### 1. P1f reductions dispatch AVX-only CPUs to AVX2 (resolved by TODO-834; native proof open)

- **Files:** `src/optimize/iter.rs:16-34`, `src/optimize/iter.rs:77-95`, `src/optimize/iter.rs:138-156`, `src/optimize/parts/cpu_dispatch.rs:1197-1201`
- **Severity:** CRITICAL
- **Impact:** Current `sum_f32`, `sum_u32`, and `sum_u64` dispatch through exact AVX512F/AVX2/SSE2 feature checks, so the former P1f-to-AVX2 route is no longer present. Native feature-limited P1f execution remains unproved; the historical defect is retained for audit traceability.
- **Fix:** TODO-834 reconciled the profile-to-kernel map in the current source. Keep the native feature-limited P1f proof lane open.
### 2. P4a moving average dispatch lacks an AVX512F proof (resolved in current route; native AVX10 proof open)

- **Files:** `src/optimize/brain.rs:721-750`, `src/optimize/brain.rs:883-931`, `src/optimize/parts/cpu_dispatch.rs:1073-1077,1209-1210`
- **Severity:** HIGH
- **Impact:** Current `moving_average` selects AVX512F, AVX2, or SSE2 from exact features and no longer dispatches by the P4a/P4b profile enum. Native AVX10.1 lane execution and profile override proof remain unclaimed; the historical direct AVX512 selection defect is retained for traceability.
- **Fix:** TODO-834 changed the current route to exact feature intersections. Keep P4a/P4b native and profile-specific proof open.
### 3. Test-only bitmap range helper mishandles reversed and clipped ranges after BMI2 dispatch gating

- **Files:** `src/optimize/transport.rs:349-390,539-568`
- **Severity:** HIGH
- **Impact:** The test/rust-tests `bitmap_set_range` dispatcher now checks `features.bmi2` before entering the BMI2 helper. The helper still does not reject `start > end`, computes `end_bit` before clipping `end_word`, and can underflow the single-word mask or fail to set the clipped final word. The parity fixture includes reversed and out-of-range ranges, but does not force the malformed profile matrix.
- **Fix:** Keep the explicit BMI2 feature gate and make the range contract fail closed before arithmetic. Add profile-specific malformed-range tests.

### 4. SSE2 short-pattern injection writes beyond the requested pattern
- **Files:** `src/optimize/stealth.rs:379-399`
- **Severity:** HIGH
- **Impact:** In the test/rust-tests-only SSE2 path, a pattern of one to sixteen bytes is zero-padded to 16 bytes and stored as a full `_mm_storeu_si128` whenever sixteen destination bytes are available. The scalar/reference behavior writes only `pattern.len()` bytes, so the accelerated path overwrites trailing data with zeros for short patterns.
- **Fix:** Preserve the requested write length in the short-pattern path and add parity tests for every length from 1 through 15 with trailing sentinel bytes.

### 5. Pattern position arithmetic is not overflow-safe before raw access
- **Files:** `src/optimize/stealth.rs:337-365`, `src/optimize/stealth.rs:450-477`
- **Severity:** HIGH
- **Impact:** Scalar, AVX2, and NEON pattern paths use unchecked `pos + pattern.len()` or `pos + i + 32` conditions before slicing or raw pointer arithmetic. A caller-supplied position near `usize::MAX` can wrap the check and reach an invalid pointer calculation. The entrypoint is test/rust-tests-only today, but its unsafe helpers still lack a fail-closed malformed-position contract.
- **Fix:** Check `pos <= data.len()` and use checked or subtraction-based bounds before every pointer offset. Add overflow-position tests for every architecture path.

### 6. SVE2 base64 encoding uses an output predicate smaller than the temporary
- **File:** `src/optimize/string.rs:301-407`
- **Severity:** HIGH
- **Impact:** The SVE2 encoder processes `groups * 3` input bytes but produces `groups * 4` output bytes. `svcntb()` limits the output predicate and store to one vector length, while `out_bytes` is larger than that vector length for every positive vector length. The code then extends `tmp_out[..out_bytes]`, including bytes that the store did not initialize. This is test/rust-tests-only but is a real correctness and unsafe-string-construction boundary on SVE2.
- **Fix:** Use a lane-safe expansion strategy with a proved output buffer and store coverage, then exercise multiple SVE vector lengths and chunk/remainder boundaries.

### 7. Packet-number decode does not enforce the QUIC length contract
- **Files:** `src/optimize/transport.rs:725-850`, `src/transport/packet.rs:498`
- **Severity:** HIGH
- **Impact:** The active packet parser supplies a header-derived length in the valid 1..=4 range, but public `decode_packet_number` accepts every nonzero `u8`. The BMI2, NEON, SVE2, and scalar paths calculate masks and shifts from that value, while `finalize_packet_number` has only a debug assertion for at most 32 bits. Invalid lengths can panic or produce undefined API semantics even though the production caller is currently bounded.
- **Fix:** Enforce the protocol range at the helper boundary and add release-mode tests for zero, valid, and invalid lengths.

### 8. VNNI aggregation silently truncates public inputs at 64 samples
- **Files:** `src/optimize/transport.rs:49-139`, `src/core_parts/connection.rs:423-429`
- **Severity:** MEDIUM
- **Impact:** `aggregate_congestion_vnni` copies only the first `CONGESTION_WINDOW_SIZE` samples into fixed arrays. The active connection caller maintains a deque bounded to 64, so no production truncation was established there. The public aggregate helper has no documented or enforced 64-sample contract, and its VNNI result diverges from scalar/AVX2 behavior for longer inputs.
- **Fix:** Make the input bound explicit or process all samples consistently, and add a >64 parity case.

### 9. Linux UDP FFI has proof and result-disposition gaps
- **Files:** `src/optimize/udp.rs:87-190`, `src/optimize/udp.rs:198-277`, `src/optimize/udp.rs:421-448`
- **Severity:** HIGH
- **Impact:** `SmallVec::with_capacity` keeps the iovec/message storage stable for the prepared batch and negative `sendmmsg`/`recvmmsg` returns are checked. The receive helper returns only the kernel count and discards every `mmsghdr.msg_len`, so callers cannot observe actual datagram lengths. Address construction copies only the active `sockaddr_in`/`sockaddr_in6` bytes into an uninitialized `sockaddr_storage` and then calls `assume_init`; the initialization proof is implicit. Batch counts are cast to `c_uint` without an explicit overflow guard. Test-only `configure_rps` can shift by 128 or more CPUs and writes a sysfs path derived directly from the interface string.
- **Fix:** Define and enforce the batch/count/length contract, make sockaddr initialization explicit, and isolate or validate test-only sysfs writes. Raw transport ownership remains cross-linked to TODO-682.

### 10. Percentile input and smaller profile intersections remain open
- **Impact:** `compute_percentile` converts unrestricted floating-point input into an index; 100, values above 100, negative values, and NaN can produce an out-of-range index or panic. The normal tests cover 0..99 only. Sort and compression vector tails were checked and no active pointer OOB was found for valid inputs, but their profile matrix is not complete. TODO-834 corrected string-search feature intersections and removed the stale SVE search symbol; SVE2 Base64 output coverage remains open.
- **Severity:** MEDIUM
- **Fix:** Specify invalid percentile behavior and add release-safe tests; complete the profile-specific proof in the owning dispatch task.

### 11. False-positive and documentation-only surfaces are separated
- **Files:** `src/optimize/telemetry.rs`, `src/optimize/sort.rs`, `src/optimize/x86_sse2.rs`
- **Severity:** LOW
- **Impact:** Telemetry's current `unsafe` matches are prose, not executable unsafe. `sort.rs`'s `TypeId` cast is mechanically tied to exact type equality, and `x86_sse2.rs` has guarded tails, but both still need formal safety sections and caller proof. TODO-836 owns the missing safety-doc surface; TODO-689 owns auxiliary dispatch/inventory cleanup.
- **Fix:** Remove stale inventory assumptions and document the actual invariants in the owning tasks.

## Audit Completion

- Read all ten affected Optimize source files, the adjacent CPU profile implementation, the direct production callers, the test-only callers, the parity/self-check fixtures, the optimization and stealth test suites, the runtime guardrail scripts, the comprehensive audit script, and the relevant TODO/history entries.
- Cross-checked all vector loads, stores, raw pointer offsets, fixed local buffers, and tail loops in `brain.rs`, `transport.rs`, `stealth.rs`, `iter.rs`, `string.rs`, `sort.rs`, `compress.rs`, and `udp.rs`. No additional active pointer out-of-bounds was established for valid input contracts beyond the findings above.
- Confirmed the profile matrix gap: the profile override fixtures exercise P0a/ARM_A0 only; no P1f or P4a/P4b proof exists. Packet-number tests cover only 1..=4, base64 tests do not prove SVE lane expansion, and pattern tests use ordinary positions. Bitmap tests do include reversed and out-of-range ranges, but not a feature-forced dispatch matrix. ISA self-checks can return early when the required feature is absent.
- Confirmed the guardrail boundary: `audit-runtime-guardrails.sh` checks a fixed list of `pub unsafe fn` names and therefore does not discover all `pub(super)` or private unsafe declarations. `audit-all-comprehensive.sh` counts textual `unsafe` and target-feature strings but does not prove profile-to-kernel intersections or malformed-input behavior.
- History reconciliation: TODO-519 commit `48a92d9` removed the historical hidden AVX-512 conversion dependency and added an AVX2 requirement to the brain AVX512 helpers; TASK 405 commit `70b0559` moved packet-number decoding into the Optimize dispatch without adding public length validation; TASK 408 commit `b67e911` bounded VNNI scratch arrays to 64; and `8e0f444` stabilized Linux batch storage but did not close receive-length or initialization proof. The old broad claims are therefore narrowed to the concrete findings above.
- No production implementation, test modification, build, runtime probe, commit, or push was performed in this audit pass. The TODO-834-owned dispatch subtasks are closed in the current source; the remaining malformed-input, public-API, FFI, VNNI, percentile, safety-documentation, and native-proof subtasks remain open.
- The current-source recheck read the TODO-834 changes in `brain.rs`, `iter.rs`, `transport.rs`, `string.rs`, `stealth.rs`, `parts/cpu_dispatch.rs`, and `transport/packet.rs`. It confirmed that TODO-834 removed the former P1f reduction-to-AVX2 profile dispatch, routes moving-average by exact AVX512F/AVX2/SSE2 features, gates the BMI2 bitmap route by `features.bmi2`, fixes the AVX2 packet-number wire byte order, and removes the stale SVE2 search symbol. The corresponding native x86/AVX10 execution proof remains external.
- The current-source recheck confirmed that the BMI2 range helper still computes `end_bit - start_bit + 1` before rejecting reversed same-word ranges and still clips `end_word` after deriving `end_bit`; short-pattern and position arithmetic remain unchecked before raw offsets; SVE2 Base64 still stores only the `svcntb()` predicate and extends the complete `out_bytes` temporary; public packet-number decode still accepts nonzero lengths outside 1..=4; VNNI still truncates public inputs to 64; and percentile conversion still permits invalid floating-point indexes.

## Current Reconciliation (2026-08-07)

| Baseline finding | Current status | Ownership and proof boundary |
|---|---|---|
| P1f reductions selected AVX2 from an AVX-only profile | Resolved in current source: `sum_f32`, `sum_u32`, and `sum_u64` use `features.avx512f`, `simd_dispatch_matrix().avx2`, and SSE2 instead of the profile enum | TODO-834 owns the implementation; native feature-limited P1f execution remains unproved |
| P4a/P4b moving-average selected AVX-512 by profile | Resolved in current source: `moving_average` selects AVX512F, AVX2, or SSE2 from exact features | TODO-834 owns the implementation; native AVX10 lanes remain unproved |
| Bitmap BMI2 route lacked a feature predicate | Dispatch remains gated by `features.bmi2`; `bounded_bitmap_end` now rejects reversed and out-of-range ranges before mask arithmetic. The malformed profile matrix is wired but native BMI2 execution is not available here | TODO-680 owns the source contract; native x86 proof remains external |
| SSE2 short-pattern store and position arithmetic | `complete_pattern_end` now validates every position before architecture-specific access, and the short path copies exactly `pattern.len()` bytes. x86/SVE native execution remains unclaimed | TODO-680 |
| SVE2 string surface | The stale SVE2 search symbol and string-search feature intersections are corrected; Base64 now limits groups to `vl/4` so output stores fit one vector. SVE2 vector-length execution remains external | TODO-834 owns search dispatch; TODO-680 owns Base64 boundary |
| QUIC packet-number and public length boundaries | AVX2 packet-number byte order is corrected, and public decode now accepts only 1..=4 while returning the expected number unchanged for invalid lengths. Broader packet/header arithmetic remains with TODO-839 | TODO-839 owns the remaining transport packet/public API remediation |
| VNNI sample bound | The public aggregate helper processes every input in bounded 64-sample chunks instead of truncating after 64. Native AVX-512VNNI execution remains unclaimed | TODO-680 |
| Linux UDP FFI | Test-only RPS interface and CPU-mask inputs now fail closed, and touched syscall/address ownership has explicit safety contracts. Shared result, receive-length, and partial-result ownership remains TODO-837; Linux execution is unavailable here | TODO-837 owns shared transport execution; TODO-680 owns the Optimize inventory |
| Percentile and auxiliary proof | Invalid percentile values now return `0.0` without mutation, and the checked index is passed to each architecture helper. TypeId and SIMD safety documentation were added; broader dispatch proof remains with TODO-689/TODO-836 | TODO-680, TODO-689, and TODO-836 retain the adjacent boundaries |

## Acceptance

- Every `unsafe` block has a `# Safety` comment.
- All SIMD intrinsics are behind explicit feature checks.
- Raw pointer loops have runtime bounds validation at the public API.
- `cargo test` and Clippy pass; no `STATUS_ILLEGAL_INSTRUCTION` regressions.
- Static source and guardrail wiring are complete. The later guarded Optimize release suite passed five suites and 43 executed tests with the disk floor maintained; native x86/BMI2/AVX10/VNNI, SVE2, Linux, sanitizer, and Miri proof remains unclaimed. Recheck today's disk and toolchains before a new run.

## Sub-Tasks

- [x] Reconcile the P1f reduction dispatch so AVX-only CPUs never reach AVX2 kernels; TODO-834 changed the current route to exact feature checks.
- [x] Define the P4a/P4b moving-average kernel feature contract in the current dispatch; native AVX10 proof remains open.
- [x] Gate bitmap BMI2 dispatch by BMI2.
- [x] Make reversed/clipped bitmap ranges fail closed and wire malformed-range proof; native BMI2/profile execution remains blocked.
- [x] Preserve short-pattern write lengths in the SSE2 injection path.
- [x] Make pattern position arithmetic overflow-safe before every slice or pointer offset.
- [x] Repair SVE2 base64 output-lane coverage and wire scalar parity at boundary lengths; native SVE2 vector-length proof remains blocked.
- [x] Enforce the QUIC 1..=4 packet-number length contract before SIMD dispatch; the separate AVX2 encode byte-order issue is closed by TODO-834.
- [x] Make the VNNI congestion sample bound explicit by processing inputs beyond 64 consistently; native AVX-512VNNI proof remains blocked.
- [x] Reconcile Linux batch count, receive-length, sockaddr initialization, and test-only RPS contracts through completed TODO-837; native Linux execution remains in the final proof gate.
- [x] Specify invalid percentile behavior and wire malformed-input coverage; the later guarded local suite passed.
- [x] Complete formal safety documentation and auxiliary dispatch proof through completed TODO-836/TODO-689.
- [ ] Inventory retained dispatched paths and their current feature predicates; run available local non-vacuity and malformed-input checks.
- [!] Run real native x86/BMI2/AVX10/VNNI, SVE2, Linux UDP, sanitizer, and Miri gates with exact host/ISA and non-vacuous test evidence before closure.
- [x] Reconcile the TODO-834 implementation delta against this umbrella audit without relabeling native x86/AVX10/SVE2 execution as locally proven.

## Notes

- Related to TODO-575, TODO-580, TODO-584.
- The 2026-08-07 recheck is a source-and-owner reconciliation only; it did not modify product or test code and did not claim native x86, AVX10, SVE2, Windows, sanitizer, or Miri execution.
- Shared transport implementation ownership is TODO-837 through TODO-842; the current Optimize-specific remaining findings stay in this umbrella owner until separately remediated.
- The implementation pass added fail-closed bitmap, pattern, packet-number, VNNI, percentile, and test-only RPS contracts, explicit safety sections, parity fixtures, and runtime guardrail 4m. It did not duplicate TODO-837's shared UDP result implementation.
- The focused Optimize test command was started with one build job and was interrupted with exit 130 after free space fell to 1.1 GiB during dependency compilation. `cargo clean` removed 1.3 GiB of generated artifacts and left 1.9 GiB free, still below the mandatory 2-GiB admission floor. No test result is claimed.

## Verification

- Commit `9ce7dbb4201cedc4d09121ba032cd110074d30df` (`TASK 680: remediate Optimize unsafe boundaries`) contains the ten tracked source, guardrail, and SSOT documentation changes; it is pushed to `origin/main`.
- Remote parity passed: local `HEAD`, `origin/main`, and `git ls-remote origin refs/heads/main` all resolve to `9ce7dbb4201cedc4d09121ba032cd110074d30df`; the tracked worktree is clean.
- `bash scripts/audits/verify-graphify-evidence.sh` completed fail-closed with `GRAPHIFY_EVIDENCE_STATUS=BLOCKED`; manifest: `scripts/out/audits/graphify-20260807T015450Z/graphify-evidence.json`. The reason remains unavailable semantic extraction, dangling or duplicate raw AST identities, unresolved or ambiguous normalized edges, incomplete coverage, and stale legacy provenance.
- `bash scripts/tests/audits/verify-audit-completeness.sh` passed with `tracked=991`, `ignored=30335`, `untracked=0`, `accounted=31326`, `current_details=370/370`, `missing_current=0`, `done_archive=441`, `explicit_archive_exceptions=36`, and `graphify=BLOCKED`.
- No build, runtime probe, native ISA execution, sanitizer, Miri, or product implementation was performed for this reconciliation.
- `cargo fmt --all -- --check` passed; `bash -n scripts/tests/audits/audit-runtime-guardrails.sh`, `git diff --check`, and locked Cargo metadata validation passed.
- `CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check --locked --lib --features rust-tests` passed before the focused test attempt. It emitted only the pre-existing unused `WintunCleanupState` and `accounting_snapshot` warnings.
- `bash scripts/tests/audits/audit-runtime-guardrails.sh` reports the new Optimize item 4m green. The aggregate remains non-zero only for four pre-existing critical findings and one pre-existing `src/simd/x86_ack.rs:3` dead-code warning.
- The focused Rust test command was not completed because of the storage floor; native x86, AVX10, SVE2, Linux, sanitizer, Miri, and Omega evidence remain unclaimed.

## Continuation Verification (2026-08-10)

- The guarded release Optimize suite completed on the current ARM64 macOS source revision `d69e10446c92be684346387d613c28340f18b25f`: five suites passed, zero failed, and zero skipped. The executed cases were I/O batch sizing (`1`), CPU profile telemetry mask (`1`), FEC batch processing (`5`), telemetry system (`7`), and SIMD/Accelerate integration (`29`), for `43` executed tests across the five suite records.
- The suite command was `CARGO_FEATURES=rust-tests bash scripts/tests/suites/test-optimization.sh --fast --output-dir scripts/out/tests/test-optimization-20260810T-backend-continuation-fast`. The authoritative manifest is `scripts/out/tests/test-optimization-20260810T-backend-continuation-fast/results.json`; its log records `Total: 5`, `Passed: 5`, `Failed: 0`, and `Skipped: 0`.
- The run started after a deliberate `cargo clean` with `20,708,952 KiB` free and finished at `9,341,304 KiB` target usage with `11,708,532 KiB` free. The 12-GiB target guard and 2-GiB free-space floor were not crossed.
- This closes the prior local Optimize release-test/storage gap. Native x86/BMI2, AVX10/VNNI, SVE2, Linux, sanitizer, Miri, and Omega evidence remain unavailable on this host; shared Linux batch/result ownership remains TODO-837, and formal adjacent proof ownership remains TODO-836/TODO-689.

## Deviations

None.
