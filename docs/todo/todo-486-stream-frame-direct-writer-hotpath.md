---
id: TODO-486
title: STREAM frame direct writer hotpath
severity: MEDIUM
phase: "R"
priority: P1
status: DONE
created: 2026-07-01
depends_on: [TODO-399, TODO-401]
---

# TODO-486: STREAM frame direct writer hotpath

## Context

The steady-state QUIC STREAM send path used the generic `Frame::Stream` encoder after first copying the queued stream bytes into a temporary `Vec`. That shape did two avoidable things on every Vec-backed stream flush:

- allocate and copy `send_buf[..body_len]` into an owned payload;
- construct a temporary `Frame::Stream` just to copy the same payload into the packet buffer.

The broad `connection_1rtt_send_recv` benchmark is dominated by crypto, packet setup, and paired connection construction, so the per-frame copy is mostly hidden there. A direct microbenchmark of the STREAM encoder isolates the hotpath and proves the removed copy.

## Desired Outcome

- Encode STREAM frames directly into the output packet buffer from the existing send buffer.
- Keep generic `frames::to_bytes(Frame::Stream)` behavior unchanged for all existing callers.
- Preserve flow-control accounting, FIN semantics, writable-stream queue behavior, and stream-ring-buffer feature compatibility.
- Add a direct benchmark that compares the previous owned-frame shape with the direct writer.

## Implementation

- Added `frames::stream_frame_wire_len(stream_id, offset, data_len)`.
- Added `frames::write_stream_frame(stream_id, offset, data, fin, out)`.
- Updated `frames::to_bytes(Frame::Stream)` to delegate to `write_stream_frame()` so the generic path remains behavior-identical.
- Updated `Connection::maybe_flush_one_writable_stream()`:
  - default Vec-backed stream buffers write STREAM frames directly from `send_buf`;
  - full-buffer flushes call `clear()` instead of `drain(0..len)`;
  - stream-ring-buffer builds keep the existing owned-vector path under the feature gate.
- Updated fin-only STREAM emission to use `write_stream_frame()` with an empty payload.
- Added `write_stream_frame_matches_generic_encoder` regression test.
- Added `stream_frame_encoding` Criterion benchmark group to `ci_regression`.

## Verification

- Local: `cargo fmt --all -- --check` pass.
- Local: `cargo test --lib --features rust-tests write_stream_frame_matches_generic_encoder` pass.
- Local: `cargo test --lib --features rust-tests stream_send_` pass.
- Local: `cargo test --lib --features rust-tests transport::connection::tests::dgram_send_recv_roundtrip` pass.
- Local: `cargo bench --bench ci_regression --features benches stream_frame_encoding -- --sample-size 20 --warm-up-time 1 --measurement-time 3` pass.
- Local: `cargo bench --bench ci_regression --features benches connection_1rtt_send_recv/payload_1400B -- --sample-size 20 --warm-up-time 1 --measurement-time 4` pass; no regression.
- Broderick: `cargo test --lib --features rust-tests write_stream_frame_matches_generic_encoder` pass.
- Broderick: `cargo test --lib --features rust-tests stream_send_` pass.
- Broderick: `cargo bench --bench ci_regression --features benches stream_frame_encoding -- --sample-size 20 --warm-up-time 1 --measurement-time 3` pass.
- Broderick: `cargo bench --bench ci_regression --features benches connection_1rtt_send_recv/payload_1400B -- --sample-size 20 --warm-up-time 1 --measurement-time 4` pass; no regression.

## Criterion Evidence

| Host | Case | Legacy owned frame | Direct writer | Result |
|------|------|--------------------|---------------|--------|
| Local | 256B | `97.7 ns` | `76.9 ns` | about 21% faster |
| Local | 1024B | `129.4 ns` | `89.6 ns` | about 31% faster |
| Local | 1400B | `139.8 ns` | `94.0 ns` | about 33% faster |
| Broderick | 256B | `158.8 ns` | `121.0 ns` | about 24% faster |
| Broderick | 1024B | `192.3 ns` | `137.2 ns` | about 29% faster |
| Broderick | 1400B | `274.6 ns` | `145.6 ns` | about 47% faster |
