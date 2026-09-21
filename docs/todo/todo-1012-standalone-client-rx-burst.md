---
id: TODO-1012
title: TODO-1012 — Standalone client RX: recvmmsg burst + persistent GRO slots
status: DONE
created: 2026-09-20
---

# TODO-1012 — Standalone client RX: recvmmsg burst + persistent GRO slots

Status: DONE (implementation + Omega e2e verification)
Priority: P2 (per-wake syscall reduction on the default CLI/e2e datapath)
Owner: core transport

## Context

The standalone client (`src/main/runtime/client.rs`) read one message per
readiness wake via `recv_connected_segments` (a single `recvmsg` with
UDP_GRO cmsg parsing). Under downlink-heavy VPN traffic each readiness wake
cost one syscall even when several datagrams were queued, and UDP_GRO alone
only helps when the kernel had already coalesced. The server shard workers
have used `recvmmsg` bursts all along; the standalone client was the last
per-wake single-syscall RX path.

## Implementation

`src/main.rs`:

- `recv_connected_burst(socket, bufs)` (Linux): one `recvmmsg` via
  `qf_transport_udp::recv_batch_gro` fills up to `RX_BURST_SLOTS = 8`
  persistent slots of `RX_BURST_SLOT_CAP = 64 KiB` each (every slot must be
  able to hold a full UDP_GRO super-buffer). Slot buffers persist across
  calls — the wake→drain cycle performs no per-packet allocation.
  `recv_batch_gro` maps `WouldBlock` to an empty result; the wrapper maps
  that back to `WouldBlock` so `async_io` keeps waiting for real readiness
  instead of spinning.
- `ConnectedRxSlot { buf_index, len, gso_size }` carries slot metadata so
  the caller can split each GRO super-buffer in place without copies.
- Non-Linux fallback: single datagram via `recv_connected_segments`
  (unchanged semantics, 1 slot).
- The old Linux `recv_connected_segments` (single `recv_msg_gro` per wake)
  was removed — it had no remaining callers. `recv_msg_gro` itself stays:
  `dns_signals.rs` and the engine `io_driver` still use it.

`src/main/runtime/client.rs`:

- Allocates `rx_bufs` once before the runtime loop (8×64 KiB on Linux,
  1×64 KiB elsewhere).
- The recv branch iterates `ConnectedRxSlot`s; the existing GRO-split
  `while seg_off < len` loop runs per slot. H3/MASQUE drain, TX flush, and
  TUN-uplink drain still run once per wake — not per datagram.

## Verification

- `cargo check --bin quicfuscate`: clean on macOS (fallback path) and on
  Omega Linux 6.17 (burst path) — no warnings.
- `tun-e2e-netns.sh` on Omega: PASS — 5/5 ICMP echo, 0% loss, clean
  routing/firewall teardown, no residue. Real client traffic flowed through
  the new `recv_batch_gro` burst path.

## Notes / follow-ups

- 8×64 KiB = 512 KiB per standalone client instance is the deliberate
  memory-for-syscalls trade; slot count is a compile-time constant.
- The engine client (`io_driver`) already has the io_uring multishot path
  (TODO-1007); this TODO covered only the standalone Tokio datapath.

## TX tail batching (same TODO, second commit)

Phase-0 measurement for TODO-1008 on Omega (`perf stat` on the standalone
client during a 15 s iperf3 TCP run through the TUN tunnel, ~18.9 Mbit/s,
single-core Neoverse N1):

- `sendmsg` 11,133 / `recvmmsg` 23,776 / `read` 31,440 / `epoll_pwait` 24,419
- The remaining `sendmsg` volume was the non-GSO tail of
  `flush_connected_outgoing`: GSO coalescing only covers contiguous
  same-length runs, so mixed-size bursts (ACK-only frames interleaved with
  MTU datagrams) fell back to one async `sendmsg` each.

Fix: after the GSO run detection, all remaining spans are emitted in a
single `sendmmsg` (`send_batch_fd`, `MSG_DONTWAIT`). A partial completion
means mid-batch backpressure — only that tail drops to the async
per-packet path, and the outer `while` retries `sendmmsg` for whatever is
left after each awaited send.

Re-measured under identical load: `sendmsg` 11,133 -> 7,632 (-31%),
`sendmmsg` 0 -> 1,874 (~5.1 datagrams per syscall), total socket-TX
syscalls -15%. The remaining `sendmsg` count is the GSO `UDP_SEGMENT`
runs themselves — already maximally coalesced.
