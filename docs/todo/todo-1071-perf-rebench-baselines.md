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
phantom numbers — they need fresh, honestly labeled measurements first.

## Scope

- Same-API AEAD cells: `R-RING` (ship default), `R-LC` (opt-in
  `rustls-aws-lc` build), `S-AEGIS` (private owner). Sizes 1200/1400, P1
  median, seal+open.
- Transport: datagram pps ceiling, handshake latency, batching efficiency.
- FEC: encode/decode throughput at current block sizes and repair ratios.
- Stealth: wire overhead per mode (bytes added, packets emitted per second).
- E2E: `tun-e2e-netns.sh` throughput on Omega netns.

## Non-goals

- No optimization work — measurement and regression gates only.
- No new benchmark harnesses unless an existing one cannot express a cell.

## Methodology

- Primary host: **Omega** (aarch64, Ubuntu 24.04, kernel 6.17, single-core
  Neoverse-N1) — the product targets Linux; Omega numbers are the baselines.
- Secondary reference: macOS developer machine — recorded and explicitly
  labeled "secondary, not representative of the Linux dataplane".
- Each cell: criterion bench or scripted run, pinned commit, recorded command,
  median + spread. Numbers go into `docs/benchmarks/` or the owning doc.
- Where a bench is missing, add it under `benches/` or `scripts/benchmarks/`
  in the same commit.

## Baseline Audit (2026-09-23)

- Local secondary host: Apple M1, Darwin 24.6.0, rustc/cargo 1.98.0; `target/` was absent and 13 GiB were free.
- Omega primary host: Linux 6.17, one Neoverse-N1 vCPU, rustc/cargo 1.97.1, batch SSH and non-interactive sudo available. Its clean checkout was fast-forwarded from `560b7e2` to `f6a867fb`; at 2026-09-23 04:24:11Z, 61 GiB were free and its old `target/` measured 566 MiB.
- Existing AEAD artifacts are not valid inputs for this rerun: the macOS artifact is pinned to `df2a846b`, while Omega reports `dirty-rsync`.
- Omega build boundary: `.cargo/config.toml` selects `~/QuicFuscate/target`; at 04:24:11Z it measured 566 MiB, then `cargo clean` at 04:25:03Z removed 2,717 files/587.3 MiB. `target/` is absent; no cache anomaly.
- Existing cells cover same-API AEAD (`bench-aead-bakeoff.sh`), Rustls packet/send-receive and FEC Criterion groups (`ci_regression.rs`, `benches/fec_pipeline.rs`), and UDP batching (`micro-udpfast-throughput.sh`). No dedicated real QUIC/TLS handshake-latency or per-mode wire-overhead cell was found.
- Omega's TUN E2E runner is available, but its fixed `/tmp/ns-*.log` paths already exist. The runner's optional traffic capture starts after its synchronous iperf ready hook, so it cannot currently measure loaded wire overhead. Use isolated logs and capture during the hook before collecting mode overhead.
- 2026-09-23 04:26Z: the first Omega AEAD runner attempt stopped at disk preflight before building because `df -g` is unsupported on Linux. Its unique `run01` metadata directory is preserved; no benchmark measurement was produced. The preflight now uses portable `df -Pk` output in 1-KiB blocks with a 2-GiB floor. A second attempt at 04:28Z on the still-pinned `f6a867fb` checkout hit the same preflight; its `run01-retry` metadata directory is preserved. The fix is local and must be committed/pulled before the next run.
- At 04:30:30Z, `scripts/tests/fast/test-benchmark-cell-contract.sh` exposed a stale assertion that treats the `selection` metadata record as a measurement cell. The first contract-test adjustment then exposed additional `scope:*` and `report` metadata records without cell IDs, including expected fast-mode `SKIP`s; validate metadata status/reason separately from measurement cells. The updated contract test and `bash -n` now pass.

## Execution Plan

1. Fast-forward Omega's clean checkout to `f6a867fb`, validate the toolchain, and start from a measured clean Cargo cache.
2. Run the same-API R-RING/R-LC/S-AEGIS bakeoff on Omega and the M1 reference with the same owners, sizes, release flags, and three repetitions. Prioritize P1 1200/1400-byte cells; retain full supporting sizes and p95/p99.

   Omega first successful-run command (run02): `cd ~/QuicFuscate && PATH="$HOME/.cargo/bin:$PATH" QF_BAKEOFF_AWS_LC=1 bash scripts/benchmarks/suites/bench-aead-bakeoff.sh --full --owners R-RING,R-LC,S-AEGIS --output-dir scripts/out/benchmarks/todo-1071-aead-omega-arm-f6a867fb-run02`

3. Run existing connection Criterion, UDP batch, and FEC pipeline cells. Add a real in-memory QUIC/TLS handshake Criterion cell and isolated loaded-pcap E2E support because those baselines are not expressed by the current benches.
4. Run TCP/UDP TUN throughput and per-stealth-mode wire captures on Omega with unique evidence paths. Report transport CPU ceilings separately from loopback/socket and netns results.
5. Consolidate commands, host/commit metadata, medians, spread, and limitations here; synchronize the owning documentation, verify, then commit and push TODO-1071 separately.

## Acceptance

- [ ] AEAD three-owner table on Omega (and macOS reference) committed.
- [ ] Transport pps/latency table on Omega committed.
- [ ] FEC encode/decode table at production block sizes committed.
- [ ] Stealth overhead table per mode committed.
- [ ] e2e throughput figure recorded with command + commit hash.
- [ ] Regression gates exist (criterion benches) for every baseline cell.

## Risks

- Single-core Omega skews absolute pps — record it, do not extrapolate.
- Thermal/noise on shared VM — repeat runs, report spread.

## Rollback

Measurement-only; nothing to roll back. Regression gates that misfire are
tuned in the same commit they were added, with the reason recorded.
