---
id: TODO-490
title: FEC decode batch benchmark truth
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-484, TODO-488]
---

# TODO-490: FEC decode batch benchmark truth

## Context

The `fec_decode_pipeline` Criterion group is supposed to protect FEC receive
behavior under clean and lossy links. Before this task, it used a single-packet
stateful loop with `on_send()` / `on_receive()` and a deterministic-random drop
decision per iteration.

That shape was not production-like:

- production hot paths reuse caller-owned send and receive scratch vectors via
  `on_send_into()` and `on_receive_into()`;
- one packet per measured iteration made heavy recovery events too sparse and
  noisy;
- the random-loss state advanced across measurements, so different samples could
  time materially different recovery work;
- Strong-mode lossy decode could look unrealistically cheap or wildly unstable.

## Desired Outcome

- Measure decode work as fixed packet batches rather than isolated single
  packets.
- Use the production scratch-reuse APIs for send and receive.
- Keep setup and prewarm outside the timed region.
- Use a deterministic 10% source-drop mask so the timed work is repeatable.
- Preserve the `fec_decode_pipeline` group name so historical Criterion output
  and scripts keep working.
- Add a separate compatibility guard for the allocating `on_receive()` wrapper
  without treating it as the production hot path.

## Implementation

- Added `DECODE_BATCH_PACKETS = 128`.
- Added `should_drop_decode_source(id)` as a fixed 10% source-drop mask.
- Replaced `fec_decode_pipeline/{mode}/no_loss` and
  `fec_decode_pipeline/{mode}/random10pct` with:
  - `fec_decode_pipeline/{mode}/batch128_no_loss_reuse`;
  - `fec_decode_pipeline/{mode}/batch128_10pct_reuse`.
- The new benchmark:
  - prewarms sender and receiver outside the timed region;
  - calls `on_send_into()` into a reused `send_output`;
  - calls `on_receive_into()` into a reused `receive_output`;
  - reports throughput as 128 decoded input elements per measurement.
- Added `fec_decode_compat_alloc/{mode}/single_packet_on_receive` as an
  allocation-cost guard for compatibility callers.
- Normalized remaining non-English FEC comments in `src/fec/mod.rs`.
- No runtime FEC logic was changed.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: no remaining source hits for the previous German FEC/H3 comment phrases.
- Local: `cargo test --lib --features rust-tests fec::` pass, 172 passed.
- Local: `cargo bench --bench fec_pipeline --features benches --no-run` pass.
- Local: `cargo bench --bench fec_pipeline --features benches -- 'fec_decode_pipeline/strong/batch128_10pct_reuse' --sample-size 10 --measurement-time 1` pass, median `7.96 ms`.
- Broderick: `cargo test --lib --features rust-tests fec::` pass, 172 passed.
- Broderick: `cargo bench --bench fec_pipeline --features benches --no-run` pass.
- Broderick: `cargo bench --bench fec_pipeline --features benches -- 'fec_decode_pipeline/strong/batch128_10pct_reuse' --sample-size 20 --measurement-time 2` pass, median `18.45 ms`.
- Broderick: `cargo bench --bench fec_pipeline --features benches -- fec_decode_pipeline --sample-size 10 --measurement-time 1` pass.

## Criterion Evidence

Broderick ARM/AArch64 measurements after the batch benchmark rewrite:

| Case | Median |
|------|--------|
| `fec_decode_pipeline/normal/batch128_no_loss_reuse` | `282 us` |
| `fec_decode_pipeline/normal/batch128_10pct_reuse` | `514 us` |
| `fec_decode_pipeline/strong/batch128_no_loss_reuse` | `278 us` |
| `fec_decode_pipeline/strong/batch128_10pct_reuse` | `17.5-18.5 ms` |
| `fec_decode_pipeline/streaming/batch128_no_loss_reuse` | `499 us` |
| `fec_decode_pipeline/streaming/batch128_10pct_reuse` | `623 us` |

## Notes

Strong-mode lossy decode is intentionally visible as the expensive emergency
recovery path. Normal and Streaming remain the practical production profiles for
typical loss and burst-loss behavior; Strong is for high-resilience conditions
where recovery cost is accepted.
