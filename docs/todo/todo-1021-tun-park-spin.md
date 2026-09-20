---
id: TODO-1021
title: Standalone TUN drain spins on latched readiness while the dgram queue backpressures
severity: HIGH
phase: L
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-1017, TODO-1020]
---

# TODO-1021: Backpressured TUN park path spins the select loop and starves the kernel queue

## Context

Surfaced by the TODO-1020 io_driver study, completing the TODO-1017
Omega forensics. Measured on Omega (single-core): ~38-44% uplink loss
at 60 M offered with reorder active - ~100% kernel TUN-queue drops
(`qtun0 TX dropped` ~= iperf loss), `send_polls` ~27x `send_datagrams`
(~96% empty `conn.send` polls). Control at 30 M: 0% loss.

## Mechanism (verified against source)

`drain_client_tun_uplink_fd` (`src/main/runtime.rs` ~L1230):

1. `send_one_tun_frame` -> `DgramQueueFull` -> `TunFrameSend::Backpressured`
   -> the drain returns `Ok(false)` with the wave parked in
   `tun_backpressure_frame` **without reading the fd again**.
2. `AsyncFd` readiness is level-triggered and stays latched until an
   inner `try_io` returns `WouldBlock`. No read ran, so the readiness
   bit is never cleared.
3. The `tun-fd-ready` select arm (`main/runtime/client.rs` ~L961)
   therefore resolves immediately on every poll: an unbounded hot
   spin. Each iteration also runs `flush_connected_outgoing`
   (>= 1 empty `conn.send` poll while the stealth window stalls) and
   a housekeeping reset - pure CPU burn while the kernel queue drops.
4. On a single core the spin starves the actual ingest/encode/emit
   work, which is what caps the loop at ~3.4-3.7k pkt/s.

Ordering is already safe: parked frames precede new reads in the same
`Vec`, and the cursor keeps FIFO.

## Objective

When the carrier backpressures, keep draining the fd into the bounded
backlog instead of early-returning - treat "queue full" exactly like
the existing `!sendable` park path: read until `WouldBlock` (clears
readiness), append to `backlog` up to `TUN_PACKET_QUEUE_CAPACITY`
(1024), drop overflow with the same bounded-channel semantics, and
count the drops in diagnostics. When the backlog is parked, new fd
frames append behind the cursor (no `send_tunnel_packet` attempt -
the queue is full anyway); send attempts resume once the backlog
drains empty.

Result: the select arm pends instead of spinning, kernel drops
become bounded counted user-space drops, and the freed CPU feeds
emission - the real lever on the measured ceiling. ~15 lines in
`drain_client_tun_uplink_fd`; the channel-based fallback
(`drain_client_tun_uplink`) already wakes on notify, so it needs the
same append-while-parked treatment only if its backlog path shares
the early return - verify during implementation.

## Acceptance

- No early return before the fd read loop while parked; readiness
  clears each wake (reads to `WouldBlock` or budget).
- Backlog stays bounded at `TUN_PACKET_QUEUE_CAPACITY`; overflow
  dropped + counted, FIFO order preserved through the cursor.
- Omega rerun (60 M UDP, reorder on): `qtun0 TX dropped` and
  `send_polls`/`send_datagrams` ratio collapse vs the TODO-1017
  baseline; document the new ceiling.
- `cargo check` + fmt + clippy clean; `tun-e2e-netns.sh` green.

## Implementation (2026-09-21, landed)

Both drains now keep consuming their source while the carrier is
backpressured instead of early-returning:

- `drain_client_tun_uplink_fd`: `Backpressured` sets `carrier_full`
  and breaks the send retry - the fd read loop keeps running and
  appends frames behind the parked cursor (bounded by
  `TUN_PACKET_QUEUE_CAPACITY` *unsent* frames: `len - cursor`), so
  `try_io` clears readiness to `WouldBlock` every wake. The select arm
  pends; no more latched-readiness spin.
- `drain_client_tun_uplink` (channel fallback): same treatment - waves
  are received and appended behind the cursor while parked, so the
  reader thread never stalls on a full bounded channel.
- Wake contract: `carrier_full` reports `Ok(false)` ("no more work")
  while the queue is full - the 5 ms active housekeeping tick (armed
  by the parked backlog) paces the retry, not a self-notify; a pure
  budget-cut still reports `Ok(true)`.
- Overflow drops are counted: new `ClientIoDiagnostics::
  tun_dropped_frames` field, surfaced as `tun_drops=` in the client
  stats line. Drain signatures take `Option<&mut ClientIoDiagnostics>`
  (same pattern as `flush_connected_outgoing`).
- FIFO preserved: appended frames queue behind `cursor`; sends resume
  in cursor order once the backlog drains.

## Validation (done, Omega `tun-e2e-netns.sh`, release build)

- 60 Mbit/s UDP (at-capacity regime): `qtun0 TX dropped = 0`,
  `tun_drops = 0`, iperf `0/55102 (0%)` loss,
  `send_polls/send_datagrams` = 1.67x (baseline ~27x, ~96 % empty).
- 140 Mbit/s UDP (saturated regime, offered > emission): `qtun0 TX
  dropped = 0`, `tun_drops = 68,984` ≈ iperf loss `68,961/128,538
  (54%)`, `send_polls/send_datagrams` = 1.72x, `transport_sent` =
  59,641 (~63 Mbit/s real emission capacity on the single-core VM).
- Semantics shift: backpressure loss is now **bounded, FIFO-ordered
  and counted** (`tun_drops`) in the userspace backlog instead of
  silently dropped in the kernel TUN queue. The backlog cap
  (`TUN_PACKET_QUEUE_CAPACITY` unsent frames) bounds memory.
- Regime caveat: `yield_window = 0` / `drain_entries = 0` in both runs —
  reorder windows did not arm (`reorder_window_tick` only runs on the
  non-wire-FEC path; wire-profile sends bypass it). The defect is
  scheduler-level and was exercised directly by the saturation run,
  so this does not block the fix — but wire-FEC-active traffic
  currently cannot arm reorder windows at all, which is a separate
  architectural gap worth a follow-up TODO.
- Gates: `cargo build --release`, `cargo clippy -D warnings`,
  `cargo fmt` clean; `client_drain_does_not_recurse_into_blocking_inner`
  green.
