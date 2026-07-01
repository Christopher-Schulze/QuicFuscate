---
id: TODO-505
title: FEC repair telemetry fastpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-480, TODO-499]
---

# TODO-505: FEC Repair Telemetry Fastpath

## Context

Broderick Criterion measurements showed persistent FEC send reuse hot paths were
still paying avoidable telemetry overhead. `AdaptiveFec::on_send_into()` updated
`emitted_ids` and `emitted_order` for every emitted packet, including
systematic/source packets.

Those structures back repair-symbol diagnostics:

- `FEC_EMITTED_UNIQUE`: unique repair-symbol IDs retained in bounded history.
- `FEC_EMITTED_ORDER_DEPTH`: bounded repair-symbol order history depth.

Tracking source packets in those repair telemetry structures was both noisy and
expensive on the common clean send path. It forced HashSet and VecDeque
maintenance even when the encoder emitted only systematic packets.

## Desired Outcome

- Keep `FEC_EMITTED_QUEUE` semantics unchanged for non-zero modes.
- Track `FEC_EMITTED_UNIQUE` and `FEC_EMITTED_ORDER_DEPTH` only for emitted
  repair packets.
- Preserve bounded repair telemetry history at 4096 entries.
- Add a regression test proving systematic-only send paths do not update repair
  telemetry.
- Avoid frontend, UI, Docker, Kubernetes, Helm, or unrelated runtime changes.

## Implementation

- Updated `AdaptiveFec::on_send_into()` to filter repair telemetry updates with
  `!packet.is_systematic`.
- Left queue-length telemetry on the non-zero-mode path intact.
- Updated resource tests and comments to describe repair telemetry accurately.
- Fixed `test_fec_resource_telemetry_accurate` to keep the last FEC output
  alive while reading `MEM_POOL_IN_USE`, because that counter is a live buffer
  ownership gauge.
- Added
  `test_fec_emitted_repair_telemetry_ignores_systematic_only_path`, proving
  systematic-only zero-mode sends leave repair telemetry counters at zero.

## Verification

| Command | Result |
|---------|--------|
| Local: `cargo fmt --all -- --check` | PASS |
| Local: `cargo test --lib fec::resource_tests -- --nocapture` | PASS, 8 tests |
| Broderick: `cargo bench --bench fec_pipeline --features benches -- "fec_send_reuse_hot_path/(light|normal|streaming)/1400B" --sample-size 10 --measurement-time 1` | PASS |

## Broderick Performance Evidence

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| `fec_send_reuse_hot_path/light/1400B` | `1.7126 us` | `1.6522 us` | `-3.7355%` |
| `fec_send_reuse_hot_path/normal/1400B` | `1.1290 us` | `1.0435 us` | `-6.4049%` |
| `fec_send_reuse_hot_path/streaming/1400B` | `374.48 ns` | `314.54 ns` | `-15.782%` |

## Notes

This keeps repair diagnostics meaningful while removing telemetry bookkeeping
from systematic-only send paths. The FEC wire format, repair cadence, mode
selection, and emitted packet semantics are unchanged.
