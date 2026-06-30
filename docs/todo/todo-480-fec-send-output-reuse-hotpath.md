---
id: TODO-480
title: FEC send output reuse hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-476, TODO-477]
---

# TODO-480: FEC send output reuse hotpath

## Status

DONE

## Context

`AdaptiveFec::on_send()` returned a freshly allocated `Vec<FecPacket>` for every
sent packet. Even after the zero-mode receive ownership fix, the clean-link send
path still paid for an output vector allocation in the Core send loop before
pushing packets into `outgoing_fec_packets`.

This allocation is unnecessary for the common case:

- Zero mode emits exactly one systematic packet.
- Normal clean windows usually emit one systematic packet and no repair packet.
- The Core already owns a per-connection state object where a reusable scratch
  buffer can live.

## Desired Outcome

Keep the existing public `on_send()` API for tests and compatibility, but make
production hot-path callers reuse a caller-owned output buffer:

- add a non-allocating `AdaptiveFec::on_send_into()` API;
- preserve all FEC emission semantics;
- wire `QuicFuscateConnection` to reuse a per-connection scratch vector;
- wire the Engine `FecCodec` wrapper to reuse a scratch vector;
- benchmark the reusable zero-mode path explicitly;
- keep focused unit tests around allocation reuse and API equivalence.

## Implementation

- `src/fec/mod.rs`: added `AdaptiveFec::on_send_into(packet, output)`.
- `src/fec/mod.rs`: retained `AdaptiveFec::on_send(packet) -> Vec<FecPacket>`
  as a compatibility wrapper over `on_send_into`.
- `src/fec/mod.rs`: transition handling now has an `*_into` variant so cross-fade
  packets also use caller-owned output buffers.
- `src/core.rs`: `QuicFuscateConnection` now keeps `fec_send_scratch:
  Vec<FecPacket>` and drains it into `outgoing_fec_packets`.
- `src/implementations/client/mod.rs`: Engine `FecCodec` now keeps
  `output_scratch` and drains it into encoded payload output.
- `src/fec/tests.rs`: added tests proving zero-mode output allocation reuse and
  first-packet output equivalence between `on_send()` and `on_send_into()`.
- `benches/fec_pipeline.rs`: added
  `fec_lazy_fast_path/zero_mode_passthrough_reuse` to measure the production
  scratch-buffer send path.

## Verification

- `cargo fmt --all -- --check`
- `cargo test --lib -- test_on_send_into_zero_mode_reuses_output_allocation test_on_send_into_matches_on_send_first_packet test_zero_mode_receive_preserves_unique_payload_owner`
- `cargo clippy --lib -- -D warnings`
- `cargo test --lib`
- `cargo bench --features benches --bench fec_pipeline -- fec_lazy_fast_path --sample-size 10 --warm-up-time 0.5 --measurement-time 1`
- Broderick: `cargo test --lib -- test_on_send_into_zero_mode_reuses_output_allocation test_on_send_into_matches_on_send_first_packet test_zero_mode_receive_preserves_unique_payload_owner`
- Broderick: `cargo bench --features benches --bench fec_pipeline -- fec_lazy_fast_path --sample-size 10 --warm-up-time 0.5 --measurement-time 1`

Local benchmark result:

- `fec_lazy_fast_path/zero_mode_passthrough`: `191.66 ns` median, about `47%`
  faster than the previous Criterion baseline.
- `fec_lazy_fast_path/zero_mode_passthrough_reuse`: `201.89 ns` median in the
  first local run with 10 samples; expected to converge closely with the wrapper
  because the wrapper now delegates to `on_send_into`.
- `fec_lazy_fast_path/normal_mode_no_loss`: no statistically significant change.

Broderick benchmark result:

- `fec_lazy_fast_path/zero_mode_passthrough`: `305.19 ns` median.
- `fec_lazy_fast_path/zero_mode_passthrough_reuse`: `286.15 ns` median.
- `fec_lazy_fast_path/normal_mode_no_loss`: no statistically significant change.

## Completion Criteria

- [x] Existing `on_send()` callers remain source-compatible.
- [x] Core send path does not allocate a fresh FEC output vector per packet.
- [x] Engine FEC wrapper reuses output scratch.
- [x] Tests prove buffer reuse and wrapper equivalence.
- [x] Focused tests, full lib tests, clippy, fmt, and FEC benchmark pass.
