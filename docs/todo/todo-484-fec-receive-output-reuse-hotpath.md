---
id: TODO-484
title: FEC receive output reuse hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-424, TODO-476, TODO-477, TODO-480]
---

# TODO-484: FEC receive output reuse hotpath

## Status

DONE

## Context

TODO-480 removed per-packet FEC output vector allocation from the send hot path
with `AdaptiveFec::on_send_into()`. The receive side still exposed only
`AdaptiveFec::on_receive() -> Result<Vec<FecPacket>, String>`, so Core and
Engine receive paths still had to allocate or accept a fresh output vector shape
for every decoded packet.

That was unnecessary for the common production cases:

- Zero mode emits exactly the incoming systematic packet.
- Normal clean windows usually emit one systematic packet and no recovered
  repair output.
- Core and Engine connection objects already own reusable per-connection state
  where a receive scratch vector can live.

## Desired Outcome

Keep the existing public `on_receive()` API source-compatible while adding a
non-allocating receive variant for production hot paths:

- add `AdaptiveFec::on_receive_into(packet, output)`;
- preserve zero-mode unique payload ownership;
- preserve systematic packet forwarding and recovery semantics;
- wire `QuicFuscateConnection` to reuse receive scratch;
- wire Engine `FecCodec` to reuse receive scratch;
- benchmark production-style normal-mode send and receive scratch reuse;
- reject any zero-mode regression.

## Implementation

- `src/fec/mod.rs`: added `AdaptiveFec::on_receive_into(packet, output)`.
- `src/fec/mod.rs`: retained `AdaptiveFec::on_receive(packet) ->
  Result<Vec<FecPacket>, String>` as a compatibility wrapper.
- `src/fec/mod.rs`: kept the zero-mode wrapper fast path direct, so compatibility
  callers do not pay the reusable-output path unless they opt into it.
- `src/fec/mod.rs`: added inline hints for `on_receive()` and
  `on_receive_into()` because both are public hot-path APIs used across crate
  boundaries.
- `src/core.rs`: `QuicFuscateConnection` now owns `fec_receive_scratch:
  Vec<FecPacket>` and reuses it through `recv_pooled_block()`.
- `src/implementations/client/mod.rs`: Engine `FecCodec` now owns
  `receive_scratch` and drains it into decoded payload output.
- `src/fec/tests.rs`: added tests proving zero-mode receive allocation reuse,
  unique payload ownership preservation, and first-packet output equivalence
  between `on_receive()` and `on_receive_into()`.
- `benches/fec_pipeline.rs`: added
  `fec_lazy_fast_path/normal_mode_no_loss_reuse` to measure the production-style
  normal-mode send and receive scratch path.

## Verification

- Local: `cargo fmt --all -- --check`
- Local: `cargo test --lib --features rust-tests on_receive_into`
- Local: `cargo test --lib --features rust-tests zero_mode_receive_preserves_unique_payload_owner`
- Local: `cargo clippy --lib --features rust-tests -- -D warnings`
- Local: `cargo test --lib --features rust-tests`
- Local: `cargo bench --features benches --bench fec_pipeline -- fec_lazy_fast_path --sample-size 10 --warm-up-time 1 --measurement-time 2`
- Broderick: `cargo test --lib --features rust-tests on_receive_into`
- Broderick: `cargo test --lib --features rust-tests zero_mode_receive_preserves_unique_payload_owner`
- Broderick: `cargo bench --features benches --bench fec_pipeline -- fec_lazy_fast_path --sample-size 10 --warm-up-time 1 --measurement-time 2`

Local verification result:

- Full library suite: 1626 passed, 0 failed.
- `fec_lazy_fast_path/zero_mode_passthrough`: `211.90 ns` median, no
  statistically significant change after the inline fast-path fix.
- `fec_lazy_fast_path/zero_mode_passthrough_reuse`: `186.33 ns` median,
  statistically improved.
- `fec_lazy_fast_path/normal_mode_no_loss`: no statistically significant change.
- `fec_lazy_fast_path/normal_mode_no_loss_reuse`: no statistically significant
  change in the short local sample, with noisy local intervals.

Broderick verification result:

- Focused FEC receive tests passed.
- `fec_lazy_fast_path/zero_mode_passthrough`: `308.03 ns` median, statistically
  improved versus the previous remote baseline.
- `fec_lazy_fast_path/zero_mode_passthrough_reuse`: `282.75 ns` median,
  statistically improved versus the previous remote baseline.
- `fec_lazy_fast_path/normal_mode_no_loss`: no statistically significant change.
- `fec_lazy_fast_path/normal_mode_no_loss_reuse`: `2.6633 us` median with a
  tight interval and no statistically significant change.

Rejected experiment:

- A borrowed `Cow::Borrowed` stream-send frame experiment in
  `src/transport/connection.rs` regressed the local `connection_1rtt_send_recv`
  benchmark, so it was reverted and not included.

## Completion Criteria

- [x] Existing `on_receive()` callers remain source-compatible.
- [x] Core receive path does not require a fresh FEC output vector per packet.
- [x] Engine FEC wrapper reuses receive output scratch.
- [x] Zero-mode receive still preserves unique payload ownership.
- [x] Tests prove buffer reuse and wrapper equivalence.
- [x] Local fmt, clippy, focused tests, full lib tests, and FEC benchmark pass.
- [x] Broderick focused tests and FEC benchmark pass without zero-mode
      regression.
