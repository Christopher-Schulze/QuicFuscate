---
id: TODO-990
title: TODO-990 — Tokio worker count defaults to available_parallelism
status: DONE
created: 2026-09-19
---

# TODO-990 — Tokio worker count defaults to available_parallelism

## Context

The runtime builder hard-fell back to `worker_threads(8)` whenever
`optimization.num_worker_threads` was unset (`0`). On single-core or small
VMs (Omega: 1 vCPU) that spawned seven workers that can never run in
parallel — pure wakeup/context-switch overhead, visible in system-wide
profiling as `tokio-runtime-w` scheduler traffic during load.

## Implementation

- `src/main/runtime.rs`: `worker_threads()` is now only invoked when the
  operator configured `num_worker_threads > 0`. Unset defers to Tokio's own
  default, which is already `available_parallelism` — so the runtime scales
  1..N with the machine instead of pinning 8.
- `docs/DOCUMENTATION.md`: config comment updated (auto = Tokio default).

## Verification

- `cargo check --bin quicfuscate`, `cargo fmt --check` clean.
- Omega scenario g A/B: 1 worker (auto) ≈ 57–58 Mbit/s vs explicit
  `num_worker_threads=8` ≈ 56 Mbit/s — no regression; identical throughput
  with 7 fewer idle workers.

## Follow-ups

- None. Operators keep full control via `optimization.num_worker_threads`.
