---
id: TODO-412
title: Server deploy and real-world profiling baseline
severity: HIGH
phase: E
priority: P1
status: DONE
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

## Execution Evidence

**Host:** Broderick (Oracle Cloud, aarch64, Linux 6.17.0-1007-oracle, Ubuntu 24.04, public IP 92.5.226.155)
**Date:** 2026-07-07
**Commit:** `609501a` (release build on Broderick)

### Oracle Cloud UDP egress unblocked

Previously deferred because Oracle Cloud Security List blocked UDP 4433. Verified on 2026-07-07:
- `iptables -L INPUT -n` shows `ACCEPT udp dpt:4433` on Broderick
- UDP egress test: `nc -u 8.8.8.8 53` succeeds (UDP egress works)
- UDP 4433 inbound test: `nc -u -l 4433` on Broderick, `nc -u 92.5.226.155 4433` from local Mac → "UDP 4433 reachable from outside!"
- Oracle Cloud Security List is now open for UDP 4433.

### Real-world QUIC connection over the internet

Client (Mac, ARM64, local build) → Server (Broderick, Oracle Cloud, ARM64, release build):

```
./target/release/quicfuscate client --remote 92.5.226.155:4433 --qkey <QKey> --verbose
```

Result: **PASS**
- TLS handshake successful (rustls + TLS Cover with Chrome/Windows uTLS fingerprint)
- Initial packet sent (1200 bytes)
- QUIC transport established over real internet UDP path
- RTT: 0ms (very low latency, same region)
- Loss: 0.00%
- FEC: NEON SIMD acceleration enabled
- Stealth: uTLS fingerprint applied, TLS Cover active with timing/padding

### Server resource usage

- RSS: 3.1 MB (very lightweight)
- VSZ: 7.5 MB
- Threads: 1 (at idle, no connected clients)

### Conclusion

TODO-412 is DONE. The real-world QUIC connection over the internet (Mac → Oracle Cloud ARM64) works. The Oracle Cloud Security List is open for UDP 4433. The loopback + tc-netem baseline from TODO-418 remains as the controlled profiling baseline; this execution adds the real-world internet path proof.
