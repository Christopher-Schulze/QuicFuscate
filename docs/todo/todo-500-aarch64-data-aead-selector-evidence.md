---
id: TODO-500
title: AArch64 data AEAD selector evidence
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-390, TODO-393, TODO-402, TODO-489, TODO-499]
---

# TODO-500: AArch64 Data AEAD Selector Evidence

## Context

The retained data-plane AEAD contract keeps two productive families:
`Aegis128L` and `Morus1280_128`. Internal AEGIS width variants
(`Aegis128X4` / `Aegis128X8`) remain implementation backends, not public
runtime config values.

Before this task, the AArch64 planner selected AEGIS when NEON and AES were
available. That was plausible from a hardware-feature perspective, but it was
not backed by a retained-backend Criterion comparison through the same packet
trait path used by the 1-RTT connection hot path.

## Desired Outcome

- Benchmark retained data-plane AEAD backends through the real packet trait path.
- Compare `Aegis128L`, `Aegis128X4`, `Aegis128X8`, and `Morus1280_128`.
- Cover single-packet `seal_batch` / `open_batch`, because `Connection`
  wraps one packet in an `AeadSealItem`.
- Cover batch8 `seal_batch` / `open_batch`, because retained X4/X8 complexity
  must justify itself under actual multi-item batch calls.
- Change AArch64 auto-selection only if Broderick evidence is clear.
- Keep x86/VAES selection unchanged.
- Avoid UI, frontend, Docker, deployment manifests, or unrelated runtime changes.

## Implementation

- Added `bench_data_aead_backends` to `scripts/benchmarks/ci_regression.rs`.
- The benchmark uses `build_data_aead_for_benches()` and
  `BenchDataAeadBackend` to construct all retained backends.
- The benchmark covers:
  - `data_aead_single_seal_batch`
  - `data_aead_single_open_batch`
  - `data_aead_batch8_seal`
  - `data_aead_batch8_open`
- Payload sizes are `64B`, `1024B`, `1400B`, and `8192B`.
- Changed AArch64 `CryptoPlan::arm_for_length()` to return
  `CryptoAeadPlan::Morus` after Broderick showed MORUS wins every tested
  retained-backend AArch64 case.
- Kept x86 selection unchanged: small payloads use AEGIS-L, mid payloads use
  AEGIS-X4, and large VAES-capable payloads use AEGIS-X8.
- Added `arm_payloads_use_morus_after_broderick_backend_evidence` as the
  planner regression test.

## Broderick Criterion Evidence

Broderick ARM/AArch64 retained-backend medians:

| Group | Size | AEGIS-L | AEGIS-X4 | AEGIS-X8 | MORUS |
|-------|------|---------|----------|----------|-------|
| single seal | 64B | `664.57 ns` | `662.89 ns` | `659.81 ns` | `455.99 ns` |
| single open | 64B | `690.81 ns` | `668.51 ns` | `681.86 ns` | `462.48 ns` |
| batch8 seal | 64B | `5.3206 us` | `5.3360 us` | `5.1914 us` | `3.5906 us` |
| batch8 open | 64B | `5.4592 us` | `5.1984 us` | `5.2269 us` | `3.5722 us` |
| single seal | 1024B | `1.6617 us` | `1.7156 us` | `1.6940 us` | `973.11 ns` |
| single open | 1024B | `1.7225 us` | `1.7444 us` | `1.7461 us` | `964.03 ns` |
| batch8 seal | 1024B | `13.614 us` | `14.039 us` | `13.441 us` | `7.6390 us` |
| batch8 open | 1024B | `13.816 us` | `13.917 us` | `13.636 us` | `7.6970 us` |
| single seal | 1400B | `2.0736 us` | `2.1367 us` | `2.1067 us` | `1.1944 us` |
| single open | 1400B | `2.1307 us` | `2.1725 us` | `2.1760 us` | `1.1885 us` |
| batch8 seal | 1400B | `16.979 us` | `17.394 us` | `16.699 us` | `9.3550 us` |
| batch8 open | 1400B | `17.115 us` | `17.221 us` | `17.010 us` | `9.4560 us` |
| single seal | 8192B | `9.1386 us` | `9.4631 us` | `9.2062 us` | `4.7539 us` |
| single open | 8192B | `9.3833 us` | `9.6699 us` | `9.7239 us` | `4.8211 us` |
| batch8 seal | 8192B | `75.755 us` | `78.250 us` | `74.768 us` | `37.883 us` |
| batch8 open | 8192B | `76.921 us` | `78.844 us` | `77.171 us` | `38.871 us` |

## Product Hot-Path Evidence

Broderick `connection_1rtt_send_recv` after the AArch64 selector change:

| Payload | Median |
|---------|--------|
| 256B | `4.6979 us` |
| 1024B | `5.5012 us` |
| 1400B | `5.8412 us` |

Broderick `connection_1rtt_stealth_compare` after the AArch64 selector change:

| Case | Median | Criterion change |
|------|--------|------------------|
| stealth_off | `5.4800 us` | `-23.558%` time |
| stealth_on | `5.5536 us` | `-23.843%` time |

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo bench --bench ci_regression --features benches --no-run` pass.
- Local: `cargo test --lib arm_payloads_use_morus_after_broderick_backend_evidence` pass.
- Local: `cargo test --lib crypto_aead_plan_length_based_selection` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- data_aead_ --sample-size 10 --measurement-time 1` pass.
- Broderick: `cargo test --lib arm_payloads_use_morus_after_broderick_backend_evidence` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- connection_1rtt_send_recv --sample-size 20 --measurement-time 2` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- connection_1rtt_stealth_compare --sample-size 20 --measurement-time 2` pass.

## Notes

This does not remove AEGIS or disable explicit AEGIS testing. It changes only
the AArch64 auto-selection policy. AEGIS remains retained for x86 hardware AES
paths, VAES/X8 evidence, explicit override, differential testing, and continued
benchmark coverage.
