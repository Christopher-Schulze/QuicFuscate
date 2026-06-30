---
id: TODO-479
title: Transport stealth heuristic RNG hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-401, TODO-416, TODO-478]
---

# TODO-479: Transport stealth heuristic RNG hotpath

## Status

DONE

## Context

The transport stealth path used cryptographically secure randomness for every
per-packet padding-rate roll, Random padding sample, BrowserMimic padding sample,
and jitter sample. Those decisions are cover heuristics, not security material.
Repeated secure OS RNG calls are unnecessary in this hot path and were visible in
the `connection_1rtt_stealth_compare/stealth_on` benchmark after clean-path H3
cover was disabled.

Security-sensitive values still require cryptographic entropy:

- connection IDs;
- path challenge bytes;
- keys, nonces, and authentication material;
- token and registry secrets.

## Desired Outcome

Keep security-critical transport randomness unchanged while moving only
non-security stealth heuristics to a fast per-thread PRNG:

- padding-rate rolls avoid per-packet secure RNG;
- Random and BrowserMimic padding samples avoid per-packet secure RNG;
- transport stealth jitter samples avoid per-packet secure RNG;
- the fast helper is clearly documented as non-cryptographic;
- tests guard bounds and non-constant output.

## Implementation

- `src/transport/pn.rs`: added `fast_rand_u64()` and
  `fast_rand_u64_uniform(max)` under `transport::rand`.
- `src/transport/pn.rs`: the fast RNG is a thread-local SplitMix64 state seeded
  once from the secure transport RNG.
- `src/transport/pn.rs`: module docs now split secure `rand_*` APIs from
  non-cryptographic `fast_rand_*` APIs.
- `src/transport/connection.rs`: per-packet stealth padding and timing
  heuristics now call `fast_rand_u64_uniform`.
- `src/transport/pn.rs`: tests cover zero max handling, upper bounds, and
  non-constant output.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --lib -- -D warnings`
- `cargo test --lib -- fast_rand transport_stealth_jitter_bounded_when_gate_active transport_stealth_jitter_disabled_when_external_pacing test_padding_random_bounds test_padding_browser_mimic_quarter_cap`
- `cargo test --lib`
- `cargo bench --features benches --bench ci_regression -- connection_1rtt_stealth_compare --sample-size 10 --warm-up-time 0.5 --measurement-time 1`

Local benchmark result:

- `connection_1rtt_stealth_compare/stealth_off`: `19.422 us` median, no
  significant performance change.
- `connection_1rtt_stealth_compare/stealth_on`: `20.704 us` median, about
  `16.7%` median improvement.

## Completion Criteria

- [x] Security-sensitive transport randomness still uses secure APIs.
- [x] Non-security stealth padding and jitter sampling avoid repeated secure RNG
      calls.
- [x] Fast helper is documented as non-cryptographic.
- [x] Focused transport tests, full lib tests, clippy, fmt, and benchmark pass.
