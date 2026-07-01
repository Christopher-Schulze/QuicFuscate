---
id: TODO-489
title: Connection benchmark hotpath isolation
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-399, TODO-401, TODO-486]
---

# TODO-489: Connection benchmark hotpath isolation

## Context

The `connection_1rtt_send_recv` and `connection_1rtt_stealth_compare`
Criterion groups are meant to protect the real 1-RTT hot path:

1. enqueue application bytes with `stream_send`;
2. build and seal a 1-RTT packet with `send`;
3. parse, open, and process it with `recv`.

Before this task, each measured Criterion iteration also constructed a fresh
paired client/server connection, installed 1-RTT secrets, configured
connection IDs, and initialized benchmark state. That setup cost dominated the
measurement and made the stealth comparison noisy.

## Desired Outcome

- Keep the same real `stream_send -> send -> recv` routine.
- Keep fresh paired connections per measured routine so state does not leak
  between iterations.
- Exclude pair construction and key installation from timed Criterion
  measurement.
- Preserve the existing benchmark group names so CI history and scripts keep
  working.

## Implementation

- Imported `criterion::BatchSize`.
- Switched `connection_1rtt_send_recv` to
  `iter_batched(bench_paired_1rtt_connections, routine, BatchSize::PerIteration)`.
- Switched `connection_1rtt_stealth_compare` to
  `iter_batched(|| bench_paired_1rtt_connections_stealth(stealth_on), routine,
  BatchSize::PerIteration)`.
- Used `PerIteration` deliberately: a paired `Connection` is large enough that
  retaining many setup values in memory would pollute the measurement.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo bench --bench ci_regression --features benches -- connection_1rtt_send_recv --sample-size 20 --measurement-time 2 --warm-up-time 1` pass.
- Local: `cargo bench --bench ci_regression --features benches -- connection_1rtt_stealth_compare --sample-size 20 --measurement-time 2 --warm-up-time 1` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- connection_1rtt_send_recv --sample-size 20 --measurement-time 2 --warm-up-time 1` pass.
- Broderick: `cargo bench --bench ci_regression --features benches -- connection_1rtt_stealth_compare --sample-size 20 --measurement-time 2 --warm-up-time 1` pass.

## Criterion Evidence

Local measurements after the isolation:

| Case | Result |
|------|--------|
| `connection_1rtt_send_recv/payload_256B` | `2.79 us` median |
| `connection_1rtt_send_recv/payload_1024B` | `3.58 us` median |
| `connection_1rtt_send_recv/payload_1400B` | `3.62 us` median |
| `connection_1rtt_stealth_compare/stealth_off` | `3.71 us` median |
| `connection_1rtt_stealth_compare/stealth_on` | `3.80 us` median |

Broderick ARM/AArch64 measurements after the isolation:

| Case | Result |
|------|--------|
| `connection_1rtt_send_recv/payload_256B` | `5.55 us` median |
| `connection_1rtt_send_recv/payload_1024B` | `7.14 us` median |
| `connection_1rtt_send_recv/payload_1400B` | `7.65 us` median |
| `connection_1rtt_stealth_compare/stealth_off` | `7.23 us` median |
| `connection_1rtt_stealth_compare/stealth_on` | `7.57 us` median |

The large apparent improvement is a benchmark-truth correction: setup work is
no longer included in the timed hotpath measurement.
