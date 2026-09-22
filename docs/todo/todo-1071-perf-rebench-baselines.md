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
