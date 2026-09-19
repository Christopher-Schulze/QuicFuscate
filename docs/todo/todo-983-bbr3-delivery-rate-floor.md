# TODO-983 - BBR3 delivery-rate floor caps throughput at ~frame_bytes/ms on fast paths

## Symptom

On Omega's namespace TUN topology (0% loss, 0ms delay, veth underlay) the
client uplink saturated at ~24-31 Mbps regardless of offered load: a 1.67
Gbit/s UDP flood produced 23.6 Mbit/s with ~98% receiver-side loss and ~948k
TX drops on `qtun0`. TCP showed the same ceiling across runs (12-53 Mbps).

The wall was not the TUN reader, the bounded uplink channel, the MASQUE
queue, or the congestion window. Per-second dataplane diagnostics showed:

- `transport_dgram_queue` ~70 (drain keeps up; queue never grows)
- `transport_bytes_in_flight` = 0 (cwnd never binds)
- `send_zero_results` ~68% of polls; `outbound_release_remaining_ms` armed
- emission ~2.8k packets/s ~= `pacing_rate` from BBR3

## Root cause

`Bbr3::bbr3_on_ack` sampled the delivery rate as

```text
delivery_rate = acked_bytes / max(now - delivered_time, 1 ms)
```

once per ACK frame. With the default `ack_eliciting_threshold = 2` each ACK
covers ~2912 B, so whenever ACKs arrive faster than 1 kHz (any path with
sub-millisecond spacing: LAN, datacenter, or this veth topology) the 1 ms
floor clamps the sample to `frame_bytes * 1k/s` ~= 2.9 MB/s ~= 23 Mbit/s.

`btlbw` is a max filter over these samples, so the estimate could never
exceed the floor-quantized ceiling. Pacing (`gain * btlbw`) then capped
emission at the same rate, which kept ACK spacing below the floor — a stable
self-referential fixed point. The old co-located profiling topology never
exposed it because loopback shortcuts bypassed the TUN path entirely.

Production impact: any QuicFuscate deployment on a sub-millisecond-RTT path
(datacenter interconnect, LAN VPN, fast metro links) was rate-limited to a
few MB/s independent of actual capacity. Both client and server directions
share this controller.

## Fix

`crates/qf-transport-cc/src/cc/bbr3.rs`:

- New `rate_window_acked` accumulator. ACK bytes are added every frame; a
  delivery-rate sample is produced only when the window anchored at
  `delivered_time` spans at least `DELIVERY_RATE_WINDOW` (1 ms). The anchor
  and accumulator reset together on window completion and on
  `on_path_change(NewAddress)` model resets.
- The sample is `rate_window_acked / window_elapsed` over a real >=1 ms
  interval — ACK spacing no longer quantizes the estimate. Sparse ACK streams
  behave exactly as before (every frame completes its own window).
- `delivered`/round accounting is unchanged and still updates per frame.

## Tests

- `delivery_rate_not_capped_by_ack_frame_spacing` — 200 ACKs of 2912 B at
  200 us spacing (~14.5 MB/s true rate); asserts `btlbw > 8 MB/s`. The old
  estimator saturates at ~2.9 MB/s and fails.
- `delivery_window_accumulates_across_dense_acks` — a sub-window ACK must not
  advance the anchor; a two-frame 1.1 ms window yields ~5.3 MB/s exactly.
- Existing delivery-clock tests (`delivery_time_advances_only_on_ack_samples`,
  `send_to_ack_gap_does_not_create_a_false_bandwidth_spike`) still pass.

## Verification

- Local: qf-transport-cc 96/96, fmt/clippy clean.
- Omega A/B (scenario g, 0% loss): `enable_pacing = false` on the client
  lifted TCP from ~12-16 to ~53 Mbit/s — confirming the pacer/estimate was
  the primary wall, not the TUN drain path.
- Post-fix Omega rerun (same topology, pacing ON): TCP **46.3 Mbit/s**
  (~3x the pinned ~16 Mbit/s), `outbound_release_remaining_ms=None` for the
  whole run — the pacer stopped gating because the estimate now tracks the
  real path rate. Under the 2 Gbit/s UDP flood the estimator became live:
  `cwnd` moved (203925 -> 20277) and the datagram queue filled/drained
  (256 -> 0) instead of freezing at the floor — the residual ~3.5k pps cap is
  the single-core testbed, not the transport.

## Testbed caveat

Omega is a single-core Neoverse-N1 VM: the runtime select loop, TUN reader
thread, crypto, and (in profiling) both endpoints plus iperf share one core.
Absolute throughput there is contention-bounded (~50-65 Mbit/s ceiling even
with pacing off); the estimator fix restores correct behavior, but multi-core
hardware is needed to measure the real ceiling. The spin-heavy `Ok(0)` flush
loop (~49k polls/s observed) is worth revisiting for CPU efficiency — see
follow-up notes in `todo.md`.
