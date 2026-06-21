---
id: TODO-418
title: Profiling-Baseline + tc-netem-Setup auf broderick
severity: HIGH
phase: "1"
priority: P0
status: DONE
created: 2026-07-23
resolved: 2026-07-23
depends_on: [TODO-413]
supersedes: [TODO-412]
---

# TODO-418: Profiling-Baseline + tc-netem-Setup

## Problem

All performance claims in the codebase are **unvalidated by real-world profiling**. Micro-benchmarks (Criterion) test isolated components but not the full data plane. The prior TODO-412 was blocked by Oracle Cloud's UDP Security List (cloud-level block, not `iptables`). Without a profiling baseline:
- TODO-390-401 (micro-opts) are blind — we don't know which are in the hot path.
- TODO-414 (Streaming-FEC) cannot be validated for latency improvement.
- TODO-416 (Gradual Escalation) cannot be validated for stealth tax.
- TODO-417 (Lock-elimination) cannot be validated for contention impact.

## Acceptance

1. **Loopback profiling baseline** captured on `broderick` (aarch64, Ubuntu 24.04, 4 cores, 23 GB RAM):
   - Server + client on `127.0.0.1`, 60-second sustained load runs.
   - `perf record` + `flamegraph` generated for each scenario.
   - Results documented in `docs/profiling/baseline-2026-07.md`.
2. **tc-netem loss/latency simulation** configured on `broderick`:
   - TUN interface or loopback alias with `tc qdisc netem` for controlled loss (0%, 2%, 5%, 10%, 25%, 50%) and latency (1ms, 50ms, 200ms).
   - Client → TUN → Server path works end-to-end.
3. **Six profiling scenarios** completed and documented:
   - (a) Pure throughput (FEC off, stealth off)
   - (b) FEC Normal mode
   - (c) FEC Extreme mode
   - (d) Stealth Performance mode
   - (e) Stealth AntiDpi mode
   - (f) Intelligent mode with synthetic probe injection
4. **Top-10 hotspots** identified per scenario in flamegraph, with file:line references.
5. **Throughput/latency/loss curves** plotted (text or CSV, no UI needed).
6. **Gate condition** for TODO-390,391,392,395,399,400,401: each scenario's flamegraph is attached as evidence.

## Fix Plan

### Step 1: Loopback profiling setup
- Build release binary on broderick (already done — verified 2026-07-23).
- Start server: `./quicfuscate server --config server.toml --bind 127.0.0.1:4433`
- Start client: `./quicfuscate client --connect 127.0.0.1:4433 --qkey {key}`
- Load generator: `iperf3` over the tunnel, or custom `dd`+`/dev/urandom` stream.
- Capture: `perf record -F 99 -g -p {server_pid} -- sleep 60` then `perf script | flamegraph.pl > server.svg`
- Repeat for client PID.

### Step 2: tc-netem setup
- Create TUN interface or loopback alias:
  ```bash
  ip tuntap add dev tun0 mode tun
  ip addr add 10.9.0.1/24 dev tun0
  ip link set tun0 up
  tc qdisc add dev tun0 root netem delay 50ms loss 5%
  ```
- Or use loopback alias:
  ```bash
  ip addr add 10.9.0.1/32 dev lo
  tc qdisc add dev lo root netem delay 50ms loss 5%
  ```
- Verify: client connects to `10.9.0.1:4433`, traffic flows through netem qdisc.
- Script the scenario matrix: `scripts/benchmarks/profiling-baseline.sh` iterating over {loss} × {latency} × {fec_mode} × {stealth_mode}.

### Step 3: Scenario runs
For each of the 6 scenarios:
1. Configure FEC mode via env (`QUICFUSCATE_FEC_*`) or config.
2. Configure stealth mode via `QUICFUSCATE_STEALTH_MODE`.
3. Run 60-second load.
4. Capture `perf record` + flamegraph.
5. Record throughput (Mbps), RTT (ms), loss (%) from client stats.
6. Save to `docs/profiling/scenario-{a-f}.csv` and `docs/profiling/flamegraph-{a-f}-server.svg`.

### Step 4: Analysis document
- Write `docs/profiling/baseline-2026-07.md`:
  - Summary table: scenario × throughput × RTT × loss × top-3 hotspots.
  - Flamegraph links.
  - Comparison: FEC off vs Normal vs Extreme (throughput cost of FEC).
  - Comparison: Stealth off vs Performance vs AntiDpi (throughput cost of stealth).
  - Recommendations: which micro-opts (390-401) are justified by evidence.

### Step 5: Synthetic probe injection (scenario f)
- For Intelligent mode: inject fake probe patterns (GFW_TLS_Probe, DPI_QUIC_Scan) via `ActiveProbeDetector` test harness or direct packet injection.
- Measure: escalation latency, throughput drop after escalation, de-escalation behavior.

## Files

- `scripts/benchmarks/profiling-baseline.sh` (new — scenario matrix runner)
- `docs/profiling/baseline-2026-07.md` (new — analysis document)
- `docs/profiling/scenario-{a-f}.csv` (new — raw data)
- `docs/profiling/flamegraph-{a-f}-*.svg` (new — flamegraphs)
- `docs/context.md` (update with findings)

## Server

- `broderick` (Oracle Cloud, Ubuntu 24.04 aarch64, 4 cores, 23 GB RAM, NL region)
- Rust 1.96.0 installed, release binary built and verified.
- `perf` and `flamegraph` tools need installation: `apt install linux-perf && cargo install flamegraph`

## Notes

- Oracle Cloud UDP block is **irrelevant** for loopback and TUN testing — no public UDP needed.
- Tailscale overlay is a secondary option for WAN-like RTT but not required for this baseline.
- This task unblocks all Phase 2/3/4 tasks — it is the single highest-leverage item.
- No UI changes. No code changes to production paths — only measurement scripts and docs.
- `perf` may require `kernel.perf_event_paranoid = 1` sysctl on broderick.
