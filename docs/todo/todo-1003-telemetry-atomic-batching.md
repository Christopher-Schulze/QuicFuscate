---
id: TODO-1003
title: TODO-1003 — Batch per-packet telemetry atomics in send/recv burst loops
status: DONE
created: 2026-09-19
---

# TODO-1003 — Batch per-packet telemetry atomics in send/recv burst loops

## Status

DONE — 2026-09-19.

## Context

Dataplane flush paths recorded telemetry with several atomic RMWs per packet,
including updates to the process-global `TransportMetrics` counters that are
shared across every worker:

- `flush_live_server_outgoing` (`src/implementations/server/live_auth.rs`)
  issued ~7 atomic RMWs per staged datagram: `telemetry::BYTES_SENT`, four in
  `record_egress_datagram` (worker + global transport counters), and two in
  `SessionStats::record_sent` — while the loop already accumulated
  `bytes_sent`/`packets_sent` locals for its own accounting.
- Client `io_driver` (`src/implementations/client/io_driver/runtime.rs`)
  issued three RMWs per span in four burst loops: the sendmmsg sent-prefix
  accounting, the tail re-send loop, the io_uring completion drain, and
  `process_inbound_batch`.
- The same function staged payloads into `Vec::new()` staging buffers, so every
  flush paid the growth-doubling chain (each `extend_from_slice` reallocated
  and re-copied prior content).

## Change

- New `Metrics::record_egress_batch(bytes, packets)` mirroring the existing
  `record_ingress_batch`; zero-packet batches are dropped.
- New `SessionStats::record_sent_batch(bytes, packets)` with the same guard.
- `flush_live_server_outgoing` now accumulates into the existing locals and
  lands one `BYTES_SENT.inc_by` + `record_egress_batch` + `record_sent_batch`
  after the drain loop; both staging vectors are `Vec::with_capacity`-sized for
  a full burst (`UDP_DATAGRAM_BURST_LIMIT` spans, 64 x 1500 B payload).
- `io_driver` burst loops accumulate `flush_*`/`batch_*` locals and flush once;
  every early-return error path flushes the accumulated counts first so totals
  match the former per-packet accounting exactly (packets are counted when
  they arrive at the socket, before `recv_mut` verdicts).

Semantics preserved: identical counter totals, identical ordering relative to
socket sends; only the atomic update frequency changed (per packet -> per
burst).

## Verification

- `cargo check`/`cargo clippy --lib`/`cargo fmt --check` clean.
- `metrics` tests: 28/28 green, including a new `record_egress_batch`
  assertion covering batch deltas and the zero-packet guard.
- `session` tests: 17/17; `io_driver` tests: 17/17.

## Files

- `src/implementations/server/metrics.rs`
- `src/implementations/server/session.rs`
- `src/implementations/server/live_auth.rs`
- `src/implementations/server/metrics/tests.rs`
- `src/implementations/client/io_driver/runtime.rs`
