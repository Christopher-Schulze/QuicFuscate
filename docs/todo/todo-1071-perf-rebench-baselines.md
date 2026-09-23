---
id: TODO-1071
title: Performance rebench and honest baselines after the crypto rebuild
severity: MED
phase: M
priority: P1
status: OPEN
created: 2026-09-22
depends_on: [TODO-1029]
---

# TODO-1071: Performance rebench and honest baselines

## Why

The crypto surface changed shape: MORUS is gone, the standard path is
ring-only, the private post-auth owner is libaegis AEGIS-128L, and ECH runs on
the pure-Rust `qf-hpke` provider. Every baseline recorded before those changes
is stale. The 1072/1073/1074 optimization clusters must not optimize against
phantom numbers - they need fresh, honestly labeled measurements first.

## Scope

- Same-API AEAD cells: `R-RING` (ship default), `R-LC` (opt-in
  `rustls-aws-lc` build), `S-AEGIS` (private owner). Sizes 1200/1400, P1
  median, seal+open.
- Transport: datagram pps ceiling, handshake latency, batching efficiency.
- FEC: encode/decode throughput at current block sizes and repair ratios.
- Stealth: wire overhead per mode (bytes added, packets emitted per second).
- E2E: `tun-e2e-netns.sh` throughput on Omega netns.

## Non-goals

- No optimization work - measurement and regression gates only.
- No new benchmark harnesses unless an existing one cannot express a cell.

## Methodology

- Primary host: **Omega** (aarch64, Ubuntu 24.04, kernel 6.17, single-core
  Neoverse-N1) - the product targets Linux; Omega numbers are the baselines.
- Secondary reference: macOS developer machine - recorded and explicitly
  labeled "secondary, not representative of the Linux dataplane".
- Each cell: criterion bench or scripted run, pinned commit, recorded command,
  median + spread. Numbers go into `docs/benchmarks/` or the owning doc.
- Where a bench is missing, add it under `benches/` or `scripts/benchmarks/`
  in the same commit.

## Baseline Audit (2026-09-23)

- Local secondary host: Apple M1, Darwin 24.6.0, rustc/cargo 1.98.0; 13 GiB were free. At 05:07:45Z, repo-local `target/` measured 655 MiB; `cargo clean` completed at 05:08:29Z, removing 3,471 files/644.1 MiB. `target/` is absent for the M1 run; no cache anomaly.
- Omega primary host: Linux 6.17, one Neoverse-N1 vCPU, rustc/cargo 1.97.1, batch SSH and non-interactive sudo available. Its clean checkout is now at `2291744478617da16993ca9823859621e7be7e21`, after fast-forwarding from `560b7e2` and receiving the portable-preflight and stale-runner fixes. At 2026-09-23 04:24:11Z, 61 GiB were free and its old `target/` measured 566 MiB.
- Existing AEAD artifacts are not valid inputs for this rerun: the macOS artifact is pinned to `df2a846b`, while Omega reports `dirty-rsync`.
- Omega build boundary: `.cargo/config.toml` selects `~/QuicFuscate/target`; at 04:24:11Z it measured 566 MiB, then `cargo clean` at 04:25:03Z removed 2,717 files/587.3 MiB. `target/` is absent; no cache anomaly.
- Existing cells cover same-API AEAD (`bench-aead-bakeoff.sh`), Rustls packet/send-receive and FEC Criterion groups (`ci_regression.rs`, `benches/fec_pipeline.rs`), and UDP batching (`micro-udpfast-throughput.sh`). No dedicated real QUIC/TLS handshake-latency or per-mode wire-overhead cell was found.
- Omega's TUN E2E runner is available, but its fixed `/tmp/ns-*.log` paths already exist. The runner's optional traffic capture starts after its synchronous iperf ready hook, so it cannot currently measure loaded wire overhead. Add opt-in `QF_E2E_LOG_DIR` and `QF_E2E_READY_CAPTURE_FILE` support to isolate existing logs and capture the UDP ready-hook load without changing default behavior.

- 2026-09-23 04:26Z: the first Omega AEAD runner attempt stopped at disk preflight before building because `df -g` is unsupported on Linux. Its unique `run01` metadata directory is preserved; no benchmark measurement was produced. The preflight now uses portable `df -Pk` output in 1-KiB blocks with a 2-GiB floor. A second attempt at 04:28Z on the still-pinned `f6a867fb` checkout hit the same preflight; its `run01-retry` metadata directory is preserved. The fix and contract-test correction were committed and pushed as `b0aae929`; Omega fast-forwarded to that revision before retrying. The first full run completed vectors, matrix, distinguish, and profile, but exited nonzero solely because the runner passed unsupported `--match-x`; preserve those artifacts, but do not accept them as the final baseline. Current libaegis X2/X4 are distinct algorithms (the qf-crypto suite asserts different ciphertext). The stale equality-runner call is removed and the old TODO-1038 artifact is labeled unpinned history; `bash -n` and the benchmark-cell contract test pass after the repair.
- At 04:30:30Z, `scripts/tests/fast/test-benchmark-cell-contract.sh` exposed a stale assertion that treats the `selection` metadata record as a measurement cell. The first contract-test adjustment then exposed additional `scope:*` and `report` metadata records without cell IDs, including expected fast-mode `SKIP`s; validate metadata status/reason separately from measurement cells. The updated contract test and `bash -n` now pass.

## Instrumentation Landed

- `connection_tls_handshake/fresh_rustls_quic_cover_off` joined the existing
  `ci_regression` transport group via `bench_rustls_quic_handshake_latency`
  (`src/transport/connection/bench.rs`). Each iteration runs a real rustls
  QUIC handshake through the in-memory packet pump with full webpki
  verification: the process-shared bench identity
  (`qftls::bench_identity_ca_path`, CA hierarchy leaf SANs `localhost` +
  `*.bench.example`) is published once per bench process, the client loads the
  CA via `verify_locations_file`, and a unique `qf-bench-<iter>.bench.example`
  SNI defeats the shared session cache so every iteration is a full
  handshake. Release builds never honor `verify_peer=false`
  (`#[cfg(debug_assertions)]` gate in `create_client_connection`), so the CA
  path is the only correct route. `qf_pki::generate_hierarchy_with_dns_sans`
  extends the single-hostname generator to multi-SAN leaves.
- `bench-transport.sh` full mode now selects
  `varint,packet_number,connection_1rtt_send_recv,connection_rustls_standard_1rtt,connection_tls_handshake,connection_1rtt_stealth_compare`;
  fast mode stays `varint`.
- `QF_E2E_LOG_DIR` isolates `ns-srv.log`, `ns-srv-restart.log`, `ns-cli.log`
  per run; when set, pre-existing log artifacts are refused. Unset keeps
  `/tmp/ns-*.log`. Hooks (`udp-ready.sh`, `tcp-ready.sh`), the
  traffic-analysis runner, and the fingerprint proof honor the same variable.
- `QF_E2E_READY_CAPTURE_FILE` makes `udp-ready.sh` tcpdump the QUIC underlay
  on `veth-cli` for exactly the synchronous iperf window (start after the
  iperf3 server is up, stop after the client finishes, refuse overwrite,
  fail on empty capture).
- The fast-mode contract test was stale on two axes: crypto cells still
  expected the pre-AEGIS three-owner list, and transport full mode only knew
  the two micro cells. Both now assert the real contract.
- Local smoke: the new cell measured ~380-400 us per fresh rustls QUIC
  handshake on the M1 reference host.

## Execution Plan

1. Fast-forward Omega's clean checkout to `22917444`, validate the toolchain, and start from a measured clean Cargo cache.
2. Run the same-API R-RING/R-LC/S-AEGIS bakeoff on Omega and the M1 reference with the same owners, sizes, release flags, and three repetitions. Prioritize P1 1200/1400-byte cells; retain full supporting sizes and p95/p99.

   Omega failed run01 command (b0aae929; stale `--match-x`): `cd ~/QuicFuscate && PATH="$HOME/.cargo/bin:$PATH" QF_BAKEOFF_AWS_LC=1 bash scripts/benchmarks/suites/bench-aead-bakeoff.sh --full --owners R-RING,R-LC,S-AEGIS --output-dir scripts/out/benchmarks/todo-1071-aead-omega-arm-b0aae929-run01`

   Omega repaired run02 command on `22917444`: `cd ~/QuicFuscate && PATH="$HOME/.cargo/bin:$PATH" QF_BAKEOFF_AWS_LC=1 bash scripts/benchmarks/suites/bench-aead-bakeoff.sh --full --owners R-RING,R-LC,S-AEGIS --output-dir scripts/out/benchmarks/todo-1071-aead-omega-arm-22917444-run02`.

   Mac reference command (run01 on `22917444`): `QF_BAKEOFF_AWS_LC=1 bash scripts/benchmarks/suites/bench-aead-bakeoff.sh --full --owners R-RING,R-LC,S-AEGIS --output-dir scripts/out/benchmarks/todo-1071-aead-macos-arm-22917444-run01`. Pre-run disk space was 13 GiB; only this TODO detail file is dirty.

3. Run existing connection Criterion, UDP batch, and FEC pipeline cells. Add only the missing real in-memory QUIC/TLS handshake cell to the existing `ci_regression` target.
4. Add opt-in `QF_E2E_LOG_DIR` and `QF_E2E_READY_CAPTURE_FILE` support to the existing TUN runner/UDP hook, preserving defaults. Run TCP/UDP throughput and `QUICFUSCATE_STEALTH_MODE` wire captures on Omega with unique evidence paths; report Criterion CPU ceilings separately from loopback/socket and netns results.
5. Consolidate commands, host/commit metadata, medians, spread, and limitations here; synchronize the owning documentation, verify, then commit and push TODO-1071 separately.

## Provisional Results (Omega, 3 successful repetitions)

Runs 02-04 passed vectors, matrix, distinguish, and profile on one Neoverse-N1 vCPU at commit `2291744478617da16993ca9823859621e7be7e21` with rustc 1.97.1. Raw outputs are in `scripts/out/benchmarks/todo-1071-aead-omega-arm-22917444-run0{2,3,4}/`. The failed `b0aae929` run01 is excluded because it invoked unsupported `--match-x`. P1 `ns/packet` repeated medians; listed p95/p99 were identical across all three runs:

| Owner | 1200 B medians; median (range); p95/p99 | 1400 B medians; median (range); p95/p99 | Runner constants, not measurements |
| --- | ---: | ---: | ---: |
| R-RING | 1120/1120/1120; 1120 (0); 1120/1160 | 1320/1320/1280; 1320 (40); 1320/1320 | 0 / 16 |
| R-LC | 1160/1160/1160; 1160 (0); 1200/1200 | 1360/1320/1320; 1320 (40); 1360/1360 | 0 / 16 |
| S-AEGIS | 680/640/680; 680 (40); 680/680 | 720/720/720; 720 (0); 760/760 | 0 / 16 |

Across successful Omega runs, the primary-cell median ranges are 0-40 ns. The printed `allocs=0 copied=16` values are constants in `examples/aead_bakeoff.rs::emit`, not measured allocation or copy counts; P2 allocates item vectors and copies each payload in the measured body. These are in-process software measurements, not wire throughput; no owner verdict is drawn until the remaining transport/FEC/stealth/E2E cells are complete.

### macOS Reference (3/3)

M1 runs 01-03 passed vectors, full matrix, distinguish, and profile at commit `2291744478617da16993ca9823859621e7be7e21` with rustc 1.98.0. Raw artifacts are in `scripts/out/benchmarks/todo-1071-aead-macos-arm-22917444-run0{1,2,3}/`. P1 `ns/packet` repeated medians; p95/p99 are the across-run ranges for each sample percentile:

| Owner | 1200 B medians; median (range); p95 / p99 range | 1400 B medians; median (range); p95 / p99 range | Runner constants, not measurements |
| --- | ---: | ---: | ---: |
| R-RING | 500/541/500; 500 (41); 500-583 / 542-625 | 583/625/625; 625 (42); 625-667 / 625-708 | 0 / 16 |
| R-LC | 458/458/458; 458 (0); 459-500 / 459-542 | 542/542/542; 542 (0); 583-625 / 584-625 | 0 / 16 |
| S-AEGIS | 292/333/292; 292 (41); 334-334 / 334-375 | 333/333/333; 333 (0); 334-375 / 375-417 | 0 / 16 |

These are secondary developer-host references only, not Linux dataplane estimates.

## Review corrections and remaining measurement work (2026-09-23)

- `scripts/benchmarks/suites/bench-fec.sh` filters for `fec_pipeline`, but
  `benches/fec_pipeline.rs` registers `fec_encode_pipeline`,
  `fec_decode_pipeline` and other named groups; `fec_matrix_mul` belongs to
  `ci_regression`. Select each intended target explicitly with its real group
  name. Fail if an expected group produces zero valid Criterion samples.
- `qf_bench_preflight` in `scripts/tests/lib/lib-common.sh` builds all bench
  targets when no target name is passed; the FEC and transport suites also
  dispatch broad `cargo bench` commands. On a constrained primary host this
  can compile unrelated libtest targets and exhaust memory before any useful
  cell runs. Preflight and execute exact `--bench` targets; record peak RSS,
  exit cause and host limit. A build-only failure is not a benchmark result.
- `scripts/tests/fast/test-benchmark-fast-mode-contract.sh` checks dry-run
  selection metadata, not the real Criterion dispatch or a nonempty sample.
  Add a bounded real-run contract test for target/filter mapping and a
  zero-sample failure fixture.
- `examples/aead_bakeoff.rs::run_p1` applies header protection but opens
  with the original, unprotected AAD. Either execute the full protect and
  unprotect roundtrip or label the cell as seal + HP + open without unprotect;
  compare owners only under identical operations. The P2 body allocates
  seal/open item vectors and copies payloads, so allocation and copy counts
  must be instrumented or reported as unavailable, separately by path.
- `measure_ns` records one `Instant` duration per operation. On the M1 some
  owner gaps are comparable to timer resolution, so use calibrated batch
  timing or Criterion with multiple samples and confidence intervals. Report
  repeat medians and p95/p99 without pretending a timer quantization step is
  an actual performance difference.
- `connection_tls_handshake/fresh_rustls_quic_cover_off` pumps packets in
  memory. Label it CPU/software handshake cost with certificate verification,
  not network handshake latency. Measure socket/netns RTT and completed dial
  separately, with the same commit and host metadata.
  The Devin CLI run at node 18908 terminated this exact Criterion cell with
  `TlsError("Read handshake error: invalid peer certificate: UnknownIssuer")`
  at `src/transport/connection/bench.rs::bench_rustls_quic_handshake_latency`.
  The current helper generates a CA/leaf hierarchy, preloads a process-wide
  server identity and loads the CA path into the client config, but that
  source chain does not explain the failed verifier outcome. Trace the
  actual certificate chain, `OnceLock` identity owner, loaded root store,
  and selected peer name on the failing run. Make the cell pass with real
  certificate verification; do not disable verification or mark a panicking
  cell as a measured baseline. Add a bounded smoke invocation that fails
  when this cell cannot complete one verified handshake.
- `scripts/benchmarks/suites/bench-crypto.sh` calls filtered
  `cargo test --release -p qf-crypto --lib ...`, records the whole command's
  `duration_sec`, and constructs `comparison.txt` from the final test-output
  token. This is test execution time, not AEAD throughput, despite its
  "Crypto Comprehensive Benchmark", "Performance comparison" and
  "Best performing configuration" wording. Its `speedup.txt` is a static
  header with no measured factors, and the best-owner scan searches for
  `16384` in test logs. A green test exit can thus yield a green benchmark
  suite with no per-byte timed crypto operation. Use the existing same-API
  AEAD benchmark cells for owner comparison; keep the filtered tests as a
  separate correctness gate with their own labels. Generate throughput and
  speedup only from parsed, nonempty timed samples of comparable operations.
- `scripts/benchmarks/ci_regression.rs` removed the
  `aes_gcm_seal/1024B` Criterion group, but both modes of
  `scripts/tests/suites/test-performance-regression.sh` still request it.
  The suite correctly fails an empty filter, so its throughput scope is
  permanently red on the present target. The fake-Cargo contract test
  (`scripts/tests/fast/test-benchmark-cell-contract.sh`) asserts only that
  this obsolete name fails under its injected empty-filter condition; it
  does not test that declared cells really exist in Criterion. Replace the
  dead cell with the actual standard rustls packet-key seal/open cells and
  the private libaegis cells at equivalent sizes; use exact registered
  names and comparable operations. A bounded real target/list proof must
  fail on any missing selected name before measuring.
- The suite sets `BASELINE_FILE` to
  `scripts/tests/suites/performance_baseline.json`, but that file does not
  exist in the current checkout. `measure_performance` labels each surviving
  sample `benchmark_completed_without_baseline` and returns PASS; its 5%
  throughput and 10% latency thresholds therefore enforce nothing. Create
  pinned, host-specific baseline data only from this task's accepted fresh
  measurements, with units and direction for each cell. Fail or explicitly
  report UNAVAILABLE when the selected host/cell baseline is missing; never
  claim a regression gate from an unbaselined PASS. The report path must
  compare compatible cells, not shallow-merge baseline/current JSON.
- `measure_performance` computes `(current-baseline)/baseline` and fails on
  a positive change for both `time` and `thrpt`. For throughput, positive
  change is an improvement and negative change is the regression; the
  present rule would invert the decision once baselines exist. The parser
  extracts only the first number from Criterion's estimate bracket and
  discards `ns`/`us`/`ms`, or throughput scale, so equal physical values
  in different printed units can compare as different numbers. Its fallback
  from missing throughput to `time` also changes the metric dimension
  mid-cell. Parse named Criterion estimates with units into canonical
  ns/op or bytes/s, store the unit and metric direction, reject mismatched
  dimensions, and apply the threshold in the correct direction. A selected
  throughput cell must not silently turn into a latency cell.
- `scripts/benchmarks/suites/bench-transport.sh` validates that Criterion
  printed a metric but writes `metric=duration_sec` and the whole
  `cargo bench` command duration as the cell value. Compilation, target
  selection and setup time can dominate that number, so the JSON cannot
  substantiate transport pps, handshake CPU cost or a before/after result.
  Parse the declared Criterion estimate and throughput for each named cell;
  retain command duration only as orchestration metadata with a separate
  key. `run_report_scope` currently shallow-merges two JSON documents via
  `jq -s '.[0] * .[1]'`, which is not a per-cell comparison and can overwrite
  evidence. Join baseline and current by stable cell/host/feature identity,
  then calculate a unit-safe delta and an explicit missing-cell result.

### Additional acceptance

- [ ] FEC encode, decode and matrix cells each invoke the intended Cargo
      target and group; a zero-sample run exits nonzero, including in a real
      bounded contract run.
- [ ] Benchmark suites preflight and run only declared target(s). A memory
      kill or compilation failure is recorded as unavailable, never as a
      successful zero-sample baseline.
- [ ] AEAD P1 operation list is exact; allocations and payload copies are
      measured per path or explicitly unmeasured. Remove constant claims from
      results, reports and dependent TODO-1039 wording.
- [ ] Primary/secondary tables separate software CPU, packet throughput and
      end-to-end network latency; repeat counts, confidence/spread, host
      limits and raw artifacts accompany every number.
- [ ] `bench-crypto.sh` never reports a test runner's wall duration as AEAD
      throughput or ranks owners from `cargo test` output. Every advertised
      comparison/speedup cell has a nonempty, unit-checked timed sample from
      the same-API harness; missing samples fail or are explicitly UNAVAILABLE.
- [ ] Every selected performance-regression filter names a registered
      Criterion cell, including standard rustls AES-GCM and private
      libaegis seal/open at comparable sizes. A real target-list contract
      rejects any deleted or zero-sample cell; fake-Cargo tests remain only
      error-path tests.
- [ ] Primary-host baselines exist for every gated cell with commit,
      hardware, feature set, unit, measurement direction and sampling
      method. A selected cell without its matching baseline never reports
      PASS for a regression threshold; a deliberate baseline-establishment
      run is labeled separately. A known worse sample fails the gate.
- [ ] A lower-throughput fixture fails, a higher-throughput fixture passes,
      a higher-latency fixture fails, and equivalent `ns`/`us`/`ms` values
      compare equal after canonical conversion. Mismatched dimensions and
      missing throughput estimates fail the exact cell rather than silently
      switching to a time metric.
- [ ] Transport-suite JSON records parsed Criterion estimate, unit,
      direction and sample identity separately from command wall duration.
      A compile-only or empty-filter run can never produce a performance
      number; the baseline/current report reconciles matching cells rather
      than merging documents wholesale.

## Acceptance

- [ ] AEAD three-owner table on Omega (and macOS reference) committed.
- [ ] Transport pps/latency table on Omega committed.
- [ ] FEC encode/decode table at production block sizes committed.
- [ ] Stealth overhead table per mode committed.
- [ ] e2e throughput figure recorded with command + commit hash.
- [ ] Every in-process baseline cell has a Criterion gate; network/E2E cells use repeatable host scripts with command, inputs, and evidence paths recorded.

## Risks

- Single-core Omega skews absolute pps - record it, do not extrapolate.
- Thermal/noise on shared VM - repeat runs, report spread.

## Rollback

Measurement-only; nothing to roll back. Regression gates that misfire are
tuned in the same commit they were added, with the reason recorded.
