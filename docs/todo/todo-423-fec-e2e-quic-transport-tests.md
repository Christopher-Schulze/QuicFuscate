---
id: TODO-423
title: E2E FEC tests through real QUIC transport (netns + tc-netem)
severity: HIGH
phase: "F"
priority: P0
status: OPEN
created: 2026-06-29
depends_on: ["TODO-422"]
---

# TODO-423: E2E FEC Tests Through Real QUIC Transport

## Problem

All 50+ existing FEC tests are **unit tests in isolation** — they test the FEC module
directly (`AdaptiveFec::on_send` / `on_receive`) but never exercise FEC through the real
QUIC transport stack. There are zero tests that verify:

1. FEC repair packets actually traverse the UDP socket → peer recv → FEC decoder pipeline.
2. FEC recovery works when real QUIC packet loss occurs (not simulated drop at FEC level).
3. FEC interacts correctly with QUIC congestion control, ACK processing, and stream flow control.
4. FEC mode transitions happen correctly during live QUIC data transfer.

The existing `examples/fec_sim.rs` is a standalone simulation — it does not use the QUIC
transport at all. The `scripts/tests/suites/test-fec-e2e-loss.sh` script runs `fec_sim`,
not a real QUIC connection.

## Goal

Build E2E tests that put FEC through the **real QUIC transport** with **real packet loss**
injected at the network layer (tc-netem), verifying end-to-end recovery.

## Implementation Plan

### 1. netns + tc-netem FEC E2E test (`scripts/tests/tun-e2e-fec-netns.sh`)

Two network namespaces over veth (reuse the TODO-422 harness pattern), with `tc netem`
injecting controlled loss:

```
ns-srv (10.10.0.1) ←── veth ──→ ns-cli (10.10.0.2)
                    tc netem loss 5%
```

Test matrix:
| Loss % | Expected FEC Mode | Expected Recovery | Max Tolerable Loss |
|--------|-------------------|-------------------|--------------------|
| 0%     | Zero/Light        | N/A               | 0%                 |
| 2%     | Normal            | >95% delivered    | <1% after FEC      |
| 5%     | Medium/Strong     | >90% delivered    | <2% after FEC      |
| 10%    | Strong/Extreme    | >85% delivered    | <5% after FEC      |
| 25%    | Extreme/Fountain  | >70% delivered    | <15% after FEC     |
| 50%    | Fountain          | >50% delivered    | <35% after FEC     |

Acceptance: `ping -c100` through tunnel with tc-netem loss → verify delivered packet count
matches expected recovery ratio. Verify FEC mode telemetry (`FEC_MODE`) escalates correctly.

### 2. Burst loss E2E test (`scripts/tests/tun-e2e-fec-burst-netns.sh`)

tc-netem can simulate burst loss patterns:
- `loss 10% 25%` — 10% average loss with 25% correlation (bursty)
- `loss 20% 50%` — heavy burst loss

Verify FEC interleaving + streaming mode handles burst patterns better than block codes.
Verify mode transitions to Streaming/Fountain under burst patterns.

### 3. Jitter + loss combined E2E test

tc-netem `delay 50ms 20ms 25%` + `loss 5%` — real-world degraded link simulation.
Verify FEC + QUIC congestion control interact correctly under jitter+loss.

### 4. Rust integration test: FEC through mock QUIC transport

A `#[test]` that creates two `QuicFuscateConnection` instances (client+server), connects
them via in-memory packet exchange, injects drops at the exchange layer, and verifies:
- FEC repair packets are generated and sent
- Lost source packets are recovered on the peer
- FEC mode escalates under sustained loss
- FEC mode de-escalates when loss stops
- No packet duplication or ordering violations

## Files to Create
- `scripts/tests/tun-e2e-fec-netns.sh` — netns + tc-netem FEC E2E test
- `scripts/tests/tun-e2e-fec-burst-netns.sh` — burst loss E2E test
- `src/fec/e2e_tests.rs` — Rust integration test (FEC through mock QUIC)

## Acceptance Criteria
- `tun-e2e-fec-netns.sh` passes on broderick for all 6 loss levels in the matrix
- FEC mode telemetry matches expected mode per loss level
- Recovery ratio meets or exceeds thresholds in the matrix
- Rust integration test passes in `cargo test --features rust-tests`
- No panics, no packet duplication, no ordering violations

## Test Environment
- Linux root + iproute2 + tc-netem (broderick or Linux CI runner)
- Build: `cargo build --release --bin quicfuscate`
- Certs: `config/local/` (reuse TODO-422 cert setup)
