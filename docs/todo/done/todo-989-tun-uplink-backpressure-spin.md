---
id: TODO-989
title: TODO-989 — TUN uplink backpressure self-notify spin
status: DONE
created: 2026-09-19
---

# TODO-989 — TUN uplink backpressure self-notify spin

## Context

`drain_client_tun_uplink` returned `Ok(true)` ("more TUN work pending") for
two structurally different stop reasons:

1. the bounded 16-frame drain limit was hit while the reader channel still
   held packets — immediate continuation is correct;
2. the QUIC DATAGRAM send queue was full (`DgramQueueFull` → `Backpressure`)
   and a frame was parked in `tun_backpressure_frame` — immediate continuation
   can never succeed until emission frees a queue slot.

Every caller maps `Ok(true)` to `tun_notify.notify_one()`, so case 2 produced
a self-sustaining wakeup loop: notify → drain → `Backpressure` → notify → …
Each iteration also ran `flush_connected_outgoing`. On the single-core Omega
VM this spin stole emission CPU on the same thread; on multi-core it burns an
unbounded wakeup rate on one core for zero useful work.

Measured (Omega, `QF_PROFILE_IPERF_UDP_RATE=1G` UDP flood through the tunnel):
1.05 Gbit/s in → ~29.7 Mbit/s out pre-fix. The same path sustains 71 Mbit/s
for self-pacing TCP — the flood's packet rate amplified the spin cost.

## Implementation

- `src/main/runtime.rs` `drain_client_tun_uplink`: both `Backpressure` exits
  (the backlog retry and the 16-frame loop) now return `Ok(false)`. The retry
  is paced by the existing machinery instead of self-notification:
  - the adaptive housekeeping tick already shortens to
    `CLIENT_HOUSEKEEPING_ACTIVE` (5 ms) while `tun_backpressure_frame` is set
    or `dgram_send_queue_len() > 0` — bounded retry + continued emission;
  - inbound datagrams re-run the drain in the recv branch;
  - the TUN reader's `notify_one` fires whenever channel space frees.
- `Ok(true)` is now returned only when the drain limit was reached and the
  channel still has work — preserving full-speed burst draining.
- The post-loop `backlog.is_some()` check became unreachable (the loop now
  returns early on backpressure) and was removed.

## Verification

- `cargo check --bin quicfuscate`, `cargo fmt --check`, `cargo clippy` clean.
- Omega A/B (`--scenario g`, UDP flood 1 Gbit/s): 29.7 Mbit/s pre-fix →
  32.9 / 28.2 / 31.2 / 33.4 Mbit/s post-fix (≈ +8%, runs share one vCPU with
  the generator, so variance is high). No regressions: PASS, 0% reported loss.

## Residual finding — flood wall is contention, not datapath

System-wide `perf record -a` during the flood: iperf3 ≈ 37–46 % CPU
(generating 1 Gbit/s on the same core), perf ≈ 23–27 %, quicfuscate ≈
24–30 % (kernel time spread thin across tun/fib/conntrack — no hotspot;
userspace a long flat tail), `client-tun-reader` ≈ 1 % (correctly parked on
the full channel). The ~30 Mbit/s wall is the available CPU share on one
Neoverse-N1 vCPU, not a datapath defect; multi-core hardware is required for
a meaningful flood ceiling.

## Follow-ups

- The per-emit copy `out[..len]` → `flat` staging in
  `flush_connected_outgoing` (~1.5 KB memcpy per datagram) is measurable only
  in the flat tail; revisit if profiling on multi-core shows it.
- `OwnedRecord` in `qf-logging` allocates `target`/`args` strings per emitted
  record on the caller thread — irrelevant at `info`, real cost only when
  hot-path `debug!`/`trace!` volume is enabled for diagnostics.
