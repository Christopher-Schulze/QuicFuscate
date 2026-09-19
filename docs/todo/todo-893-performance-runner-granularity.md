---
id: TODO-893
title: Modularize the Performance regression runner and artifact report path
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-08-14
depends_on: [TODO-890]
---

# TODO-893: Modularize the Performance Regression Runner and Artifact Report Path

## Objective

Make scripts/tests/suites/test-performance-regression.sh selectively executable by measurement dimension, while preserving the current benchmark IDs, thresholds, Criterion validation, baseline comparison, fast/full cell lists, optional library filters, output schema, and fail-closed status semantics.

The same task must close the adjacent artifact truth gap: the runner assigns CURRENT_FILE="$OUTPUT_DIR/performance_current.json" and later attempts to merge it with the baseline, but the current runner and its shared helper call sites do not visibly produce that file. Granular selection is not complete if the report branch remains unreachable or can describe a file that was never generated.

This is a test-harness and evidence-contract task only. It does not authorize product performance changes, benchmark threshold tuning, compiler-flag changes, frontend/Tauri changes, or claims about native platforms that are unavailable on this host.

## Why

The runner is currently a 533-line linear script with two very different kinds of work:

- Criterion benchmark cells that require the ci_regression bench target, optimized build flags, benchmark output parsing, baseline lookup, metric validation, and regression thresholds.
- Optional release library tests for memory, pool, CPU, and scalability behavior that use target-scoped discovery and do not require the benchmark target.

Every invocation performs common setup and then traverses throughput, latency, memory, CPU, hot path, SIMD, scalability, and report sections. A focused question such as "did the sort_simd comparison regress?" currently pays for unrelated benchmark cells and optional library discovery. A focused memory test still performs benchmark preflight even though it does not consume Criterion.

The existing fast profile reduces benchmark IDs and skips memory/CPU and SIMD, but there is no explicit way to request one skipped dimension. The neighboring scoped suites establish the desired --only contract with explicit omission records and validated scope names.

The report path also needs correction before it can be trusted. The source sets CURRENT_FILE at scripts/tests/suites/test-performance-regression.sh:31-33, but the visible runner only reads it at the merge branch near lines 509-525; a repository search found no writer in this runner or in the shared benchmark record call sites. The task must resolve whether the intended producer is the summary JSON, a normalized snapshot, or a missing export step, then implement one explicit schema-preserving producer. It must not silently merge two unrelated documents or overwrite the baseline.

## Verified Current State

The following inventory is source-derived from scripts/tests/suites/test-performance-regression.sh, scripts/tests/fast/test-benchmark-cell-contract.sh, and scripts/tests/utils/util-run-full-suite.sh:

| Current block | Current cells or filters | Proposed scope | Current fast behavior |
|---|---|---|---|
| Throughput | aes_gcm_seal/1024B, data_aead_single_seal_batch/aegis128l_1400B; full adds morus_encrypt/1024B and morus_decrypt/1024B | throughput | Two cells |
| Latency | connection_1rtt_send_recv/payload_1024B, stream_frame_encoding/1024B_direct_writer; full adds header_validate/short_and_long | latency | Two cells |
| Memory | Optional memory_usage and pool_efficiency library filters | memory | Omitted and represented by the current combined memory/CPU skip record |
| CPU | Optional cpu_usage library filter | cpu | Omitted and represented by the current combined memory/CPU skip record |
| Hot path | varint/roundtrip_8vals; full adds packet_number/encode_all_lengths | hotpath | One cell |
| SIMD | x86 sort_simd/1024_elems measured with without_avx2 and with_avx2; non-x86 explicit platform skip | simd | Omitted with a fast-profile skip record |
| Scalability | Optional scalability_10, scalability_100, scalability_1000, streams_10, streams_100, streams_1000; fast selects only 100 for each family | scalability | Two optional filters at 100 |
| Report | Optional baseline/current merge through jq | report | Current branch runs only when both files happen to exist |

The fixed regression thresholds must not change:

| Metric | Current threshold |
|---|---:|
| Throughput degradation | 5 percent |
| Latency degradation | 10 percent |
| Memory degradation | 15 percent |
| CPU degradation | 10 percent |

Benchmark setup is also dimension-dependent:

- The existing benchmark preflight checks the ci_regression target before benchmark cells are run.
- Full mode builds with native optimization flags before benchmark measurement.
- Memory, CPU, and scalability optional tests use the release library discovery path and can run without a present benchmark target.
- Report-only work must read existing artifacts and must not compile or execute benchmarks.

## Canonical Scope Contract

The runner must expose exactly these scope names plus all:

| Scope | Owns | Benchmark target required | Optional test discovery required |
|---|---|---:|---:|
| throughput | Throughput benchmark cells and baseline comparison | Yes | No |
| latency | Latency benchmark cells and baseline comparison | Yes | No |
| memory | memory_usage and pool_efficiency filters | No | Yes |
| cpu | cpu_usage filter | No | Yes |
| hotpath | Hot-path benchmark cells and baseline comparison | Yes | No |
| simd | x86 AVX2 comparison or explicit non-x86 skip | Yes on x86 | No |
| scalability | Connection and stream scalability filters | No | Yes |
| report | Current snapshot validation and optional baseline merge | No | No |

all remains the default and is not a ninth execution section. Scope names must use the existing shared validator and must not be interpreted as shell code.

## Fast and Full Semantics

1. No --only and --fast preserve the exact current reduced cells, memory/CPU skip behavior, SIMD skip behavior, scalability 100 selection, and report behavior after the artifact repair.
2. No --only and no --fast preserve the exact full cells, thresholds, optional filters, x86 comparison, scalability arrays, and report order.
3. An explicit --only selection overrides the default fast omission for the requested scope, matching the neighboring scoped runners. For example, --fast --only memory runs the existing memory filters instead of silently omitting them; it does not invent a reduced memory metric.
4. --fast --only throughput, latency, or hotpath uses the existing fast cell list for that selected scope. --fast --only scalability uses the existing 100 connection and stream filters. --fast --only simd explicitly runs the SIMD comparison on x86 despite the unscoped fast omission.
5. --only report performs no benchmark preflight, optimized build, Criterion run, or optional library discovery. It validates the current artifact and performs the report operation only.
6. --only combinations run their selected scopes in canonical order, not in user-supplied order. The requested selection is retained in metadata so the normalization is auditable.
7. Every omitted scope receives an explicit SKIP record. In unscoped fast mode the reason is fast_profile_omits_scope for memory, CPU, and SIMD; in explicit selection it is not_selected_by_scope.

## Current Snapshot and Report Contract

The following contract must be resolved before the task can close:

- performance_current.json is a per-run snapshot of validated measured cells, keyed by stable benchmark cell and metric. It contains current values only and never copies baseline values into current fields.
- The snapshot includes provenance needed to interpret a value: effective mode, selected scopes, benchmark target, feature set, effective RUSTFLAGS, command status, output path, and metric validation state.
- A benchmark command that exits zero but matches no cell, emits no numeric metric, or emits a non-numeric metric cannot enter the current snapshot as a PASS value. It remains a FAIL item in performance_results.json.
- If no selected scope produces a current measurement, unscoped execution records an explicit SKIP report item with a named reason. An explicit --only report request fails closed because a requested report cannot be produced without a current artifact.
- A missing baseline is not a benchmark failure by itself. The runner records benchmark_completed_without_baseline and still writes the current snapshot. An invalid or unreadable baseline metric is a FAIL for the affected cell, matching current fail-closed comparison behavior.
- The merge operation must not overwrite performance_baseline.json, must not mutate previous output directories, and must use the existing JSON tooling or an equivalent validated serializer.
- The report item records whether merge occurred, whether baseline was absent, and the exact reason for any unavailable or failed report. A warning without a machine-readable status is not sufficient.

## Implementation Plan

1. Freeze the current full and fast cell lists, section order, thresholds, target names, feature sets, environment assignments, and expected result identities. Extend the existing benchmark-cell contract inventory before editing dispatch.
2. Add ONLY=all and a validated --only parser while retaining --fast, --output-dir, --rustflags, and --verbose. Update help with the exact scope vocabulary.
3. Add a selection record containing requested scopes, canonical order, effective mode, and benchmark setup requirements. Add explicit SKIP records for every omitted scope before running selected work.
4. Split the current linear body into named scope owners. Keep measure_performance as the single benchmark measurement implementation, run_optional_cargo_test as the single library-test implementation, and the shared JSON record helpers as the single serialization path.
5. Add a dependency decision before benchmark preflight. Only run the benchmark-target preflight and optimized build when the normalized selection contains throughput, latency, hotpath, or simd on x86. Memory, CPU, and scalability-only runs must not pay for the benchmark target.
6. Preserve benchmark setup flags exactly. Keep BENCH_RUSTFLAGS, RUSTFLAGS_EXTRA, target CPU, optimization level, and the current no-global-LTO rule. Do not add a new global RUSTFLAGS mutation while extracting scopes.
7. Keep measure_performance fail-closed. Every selected Criterion cell must retain the exact filter-banner check, numeric metric validation, command status, baseline lookup, threshold comparison, raw output path, and result reason.
8. Split memory and CPU from the current combined RUN_MEM_CPU block. The default order remains memory then CPU. Fast mode records two explicit scope skips rather than one opaque combined row, while the unscoped compatibility summary may retain a separate aggregate only if it remains additive and unambiguous.
9. Keep SIMD architecture logic inside run_simd_scope. x86 runs both AVX2 comparison cells with their existing flags; non-x86 emits the existing platform skip. No host architecture is simulated by changing uname or forcing an unsupported target feature.
10. Keep scalability arrays and optional discovery unchanged. The selected scope must not run a connection test when only stream scalability was requested unless the canonical scope is deliberately defined as both families and documented as such. The preferred contract is that scalability owns both families because that matches the existing section and keeps the user vocabulary compact; the JSON cells remain individually identifiable.
11. Implement write_current_snapshot or its equivalent at one explicit point after selected measurements. It must consume validated current values, preserve cell/metric identity, and create performance_current.json exclusively inside the current output directory.
12. Implement run_report_scope against the snapshot contract. Validate JSON shape and numeric values, handle absent baseline versus invalid baseline distinctly, and record PASS, SKIP, or FAIL in performance_results.json with exact reasons. Do not use a blind jq -s merge as the only validation.
13. Add a real scope and artifact contract fixture under scripts/tests/fast/. It must prove benchmark-only selection skips optional tests, memory-only selection skips benchmark preflight, report-only selection performs no Cargo command, empty benchmark filters fail, current snapshots contain only measured cells, and baseline files are never overwritten.
14. Reconcile util-run-full-suite.sh. Top-level --only performance continues to invoke the same runner once. The default fast/full invocation continues to pass only --fast as before. Do not make the full-suite utility duplicate the report or benchmark setup.
15. Update docs/DOCUMENTATION.md and docs/MAP.md after implementation with the exact scope list, benchmark dependency gating, snapshot/report schema, threshold preservation, and explicit native-platform limits.
16. Re-read every changed script and fixture, run shell syntax and warning-level ShellCheck where available, execute the contract fixture, and run representative selected scopes with isolated output directories. Record unavailable native benchmark or cross-platform evidence explicitly.
17. Compare unscoped full and fast artifacts against the frozen inventory. Any missing cell, changed threshold, changed command environment, hidden preflight, duplicate benchmark, baseline mutation, or dead report branch blocks closure.

## Acceptance Criteria

- test-performance-regression.sh --help lists exactly throughput,latency,memory,cpu,hotpath,simd,scalability,report for --only.
- Unscoped full and fast invocations preserve the current benchmark cells, optional filters, thresholds, architecture skips, order, and result reasons.
- Every individual scope and valid combination runs only selected work and emits explicit omitted-scope records.
- Benchmark preflight and optimized build occur only when a selected scope needs a benchmark target; memory, CPU, scalability, and report-only runs do not compile benches.
- Every selected benchmark cell retains the existing non-vacuity proof: exact filter banner plus validated numeric metric. Empty filters fail even when Criterion exits zero.
- Memory and CPU are independently selectable while retaining the current default order and filter identities.
- SIMD comparison remains x86-only with an explicit non-x86 skip and no fabricated cross-ISA result.
- performance_current.json is generated from actual validated measurements, is schema-valid, is isolated to the current output directory, and never overwrites the baseline.
- --only report does not invoke Cargo, reports missing current data as a fail-closed result, and distinguishes absent baseline from invalid baseline.
- Report merge status and reasons are machine-readable; warnings alone cannot make a report appear green.
- The full-suite utility invokes the performance runner exactly once per selected top-level scope and does not duplicate benchmark setup.
- No Rust source, benchmark threshold, crypto/FEC implementation, frontend source, Tauri host, visual asset, animation, style, layout, copy, or approved Rotate button changes as part of this task.

## Verification Matrix

| Gate | Required evidence | Expected result |
|---|---|---|
| Shell parse | bash -n scripts/tests/suites/test-performance-regression.sh and the new fixture | Exit 0 |
| Static shell quality | Warning-level ShellCheck on changed shell files when installed | No new diagnostics |
| Help and validation | Help, unknown scope, empty scope, malformed list | Help 0; invalid input 2 |
| Benchmark scope | --only throughput, latency, hotpath, simd | Only requested benchmark cells and required preflight/build |
| Library scope | --only memory, cpu, scalability | Optional filters only; no benchmark preflight/build |
| Report scope | --only report with valid, missing, and malformed current/baseline artifacts | No Cargo; explicit PASS/SKIP/FAIL semantics |
| Fast semantics | Unscoped --fast and explicit --fast --only for omitted scopes | Current reduced set preserved; explicit request honored |
| Criterion non-vacuity | Existing empty-filter failure injection | FAIL, named reason, nonzero aggregate |
| Snapshot integrity | Parse performance_current.json and performance_results.json | Current values are measured-only and provenance-complete |
| Baseline immutability | Hash baseline before and after report/benchmark runs | Byte-identical baseline |
| Full-suite consumer | util-run-full-suite.sh --only performance with isolated output | One runner invocation and valid aggregate metadata |
| Documentation/diff | git diff --check, complete read-back, protected-path diff audit | Clean local diff; no frontend/Tauri visual delta |

## Primary Files and Owners

- scripts/tests/suites/test-performance-regression.sh
- scripts/tests/suites/performance_baseline.json (read-only contract input unless a separate approved baseline task exists)
- scripts/tests/fast/test-benchmark-cell-contract.sh
- scripts/tests/fast/test-performance-scope-contract.sh (new scope and artifact fixture if needed)
- scripts/tests/utils/util-run-full-suite.sh
- scripts/tests/lib/lib-common.sh only for a proven shared artifact/helper gap
- docs/DOCUMENTATION.md
- docs/MAP.md
- docs/todo.md
- docs/todo/todo-893-performance-runner-granularity.md

## Non-Goals

- Changing any benchmark threshold, benchmark ID, Criterion configuration, optimization flag, or performance acceptance policy.
- Replacing baseline comparison with a new statistical method.
- Claiming a performance improvement from a faster runner. This task measures execution scope and evidence integrity, not product throughput.
- Moving Optimization, FEC, crypto, or transport benchmarks into this runner.
- Creating a second current-result schema or a report-only compatibility script.
- Touching any frontend or Tauri visual property. The established visual output and approved Rotate control remain frozen.

## Risks and Fail-Closed Rules

- The largest risk is selecting one benchmark scope while still compiling or executing unrelated dimensions. Contract fixtures must observe command identity, not only the final exit code.
- The current snapshot gap must not be papered over by copying performance_results.json or baseline data into a file with a misleading name.
- Criterion can exit zero for an empty filter. The banner and numeric metric checks remain mandatory for every selected cell.
- Missing benchmark prerequisites are explicit SKIP only when the target is genuinely absent; a target build failure remains FAIL.
- A missing baseline is a named no-baseline state, not a fabricated zero or a pass that hides the absence.
- Never mutate performance_baseline.json, overwrite prior run directories, use || true, or suppress command status.
- Do not change production code or the frozen frontend to simplify performance measurement.

## Deviations

None.
