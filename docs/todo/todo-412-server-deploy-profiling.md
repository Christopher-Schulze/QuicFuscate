---
id: TODO-412
title: Server deploy and real-world profiling baseline
severity: HIGH
phase: E
priority: P1
status: DEFERRED
superseded_by: TODO-418
created: 2026-06-05
---

# TODO-412: Server Deploy + Real-World Protocol Profiling

> **Note (2026-07-23):** This task is **superseded by TODO-418** (Profiling-Baseline + tc-netem-Setup). The original TODO-412 was blocked by Oracle Cloud's UDP Security List (cloud-level block, not `iptables`). TODO-418 uses a pragmatic loopback + tc-netem approach that bypasses the Oracle UDP block entirely. Do not implement this task separately.

## Problem

Micro-benches and CI do not reflect production server load (Linux, systemd, real NIC, real clients). User has a server available for install but no baseline metrics captured.

## Acceptance

- Release artifact installed via `install-server-linux.sh`
- Baseline captured: throughput, CPU%, p99 latency, FEC mode distribution, AEAD backend selected
- Results recorded in `docs/profiling/` and linked from `docs/DOCUMENTATION.md` when they become project truth
- Install runbook validated (certs, firewall, admin bind)

## Fix Plan

1. Download `quicfuscate-server-linux` artifact from GitHub Actions (Release Build workflow)
2. Install on user server with TLS certs
3. Run `scripts/benchmarks/` or iperf-style VPN test if available
4. Capture `quicfuscate` telemetry / logs for Brain/FEC/CC decisions
5. Compare against TODO-399 bench numbers

## Files

- `scripts/install/install-server-linux.sh`
- `config/server-linux.default.toml`
- `.github/workflows/release.yml`

## Blockers

- User server SSH access details
- TLS cert paths
- Profiling target definition

## Note

No UI changes. Server admin web assets deployed as-is from build.
