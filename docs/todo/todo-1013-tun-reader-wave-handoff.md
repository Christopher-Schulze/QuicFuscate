# TODO-1013 — TUN reader: wave-batched channel handoff

Status: DONE (implementation + Omega A/B measurement + e2e verification)
Priority: P3 (wakeup/synchronization amortization on the TUN uplink)
Owner: interface / standalone client runtime

## Context

The `perf stat` syscall-mix snapshot taken for TODO-1008 showed the TUN
reader thread dominating the standalone client's syscall surface:
~2000 `read` calls/s (the fd delivers one frame per read - the kernel has
no multi-frame TUN read API), each followed by one `sync_channel::send`
(Mutex+futex) plus one `Notify::notify_one`. The fd cannot be batched, but
the handoff can.

## Implementation

- `qf_transport_types::TUN_READ_BURST = 32`: wave cap.
- `TunInterface::reader_loop_with_shutdown_batched` (`src/interface.rs`):
  after the first packet of a wave, the fd is drained nonblocking until
  `WouldBlock` or the wave cap, then the callback fires once with the whole
  `Vec<TunPacket>`. Mid-wave read errors flush the collected wave before
  propagating - no silent packet loss. The fd is `O_NONBLOCK`
  (`interface.rs` open path already sets it), so drains are free of
  blocking risk.
- Standalone client (`src/main/runtime/client.rs`): channel becomes
  `sync_channel<Vec<TunPacket>>` bounded to
  `ceil(TUN_PACKET_QUEUE_CAPACITY / TUN_READ_BURST)` waves, preserving the
  ~1024-packet backpressure budget.
- `drain_client_tun_uplink` (`src/main/runtime.rs`): consumes waves under a
  per-invocation frame budget (`TUN_DRAIN_FRAME_BUDGET = 128`) so oversized
  waves cannot starve other select arms; backpressured or budget-cut
  remainders park as `(Vec<TunPacket>, cursor)` in the existing backlog
  slot, keeping the 5 ms housekeeping re-arm contract intact.

## Measured (Omega, 15 s iperf3 through TUN, single-core N1)

A/B against the immediate baseline (same tree minus this change):

| syscall | baseline | batched | delta |
|---|---|---|---|
| epoll_pwait | 28,488 | 24,333 | -15% |
| futex | 32,820 | 30,850 | -6% |
| read | 28,566 | 33,828 | +18% (drain probes) |
| total syscalls | ~134k | ~127k | -5% |

Throughput unchanged (iperf TCP stream is the worst case for batching:
steady single packets; bursty multi-flow traffic batches harder). The
trade is deliberate: one extra nonblocking `read` probe per wave buys the
wake+lock amortization.

## Verification

- `cargo check --bin quicfuscate`: clean on macOS and Omega Linux.
- `tun-e2e-netns.sh` on Omega with the batched binary: PASS (5/5 echo both
  directions, 0% loss, clean teardown).

## Server datapath (same change set)

The standalone server reader (`runtime_impl.rs`) had the identical
per-packet `send`+`notify` pattern - hotter still, since it aggregates
every client's uplink. Same conversion:

- Channel: `sync_channel<Vec<TunPacket>>`, bound wave-counted to preserve
  the ~1024-packet backpressure budget.
- `drain_server_tun_packets` (`tun_path.rs`) consumes waves under the
  existing 32-frame budget; a partially drained wave parks in the caller's
  `pending_wave` (`std::vec::IntoIter` carries the remainder position
  intrinsically) and resumes before new waves, preserving the `Ok(true)`
  re-arm contract.
- Verified on Omega via `tun-e2e-netns.sh` with the batched server binary:
  PASS, 0% loss both directions, clean teardown.

## Follow-up: reactor-integrated uplink (AsyncFd) - supersedes the channel

The wave batching above amortized the reader thread, but the thread itself
was only needed because the TUN fd lived outside the Tokio reactor. The fd
is already `O_NONBLOCK`, so on unix the standalone client now registers it
via `tokio::io::unix::AsyncFd` (`TunReadSource`, `src/main/runtime.rs`) and
reads uplink frames as an ordinary `select!` branch - reader thread,
channel, `ppoll`, and notify chain all removed for the client path.

Bug found during e2e validation (worth recording): the readiness branch
initially gated the drain on `masque_tunnel_established() && h3_stream_id`.
AsyncFd readiness stays latched until an inner read returns `WouldBlock`,
so skipping the read left the bit set and the branch spun (1.35M
`readable()` resolves in 14 s, zero reads, 100% ping loss). Fix: the drain
always runs on a readiness fire; frames read before the carrier is ready
park in the bounded backlog (`TUN_PACKET_QUEUE_CAPACITY`), exactly the
buffering the reader channel used to provide. `drain_uplink_any` now
dispatches fd-vs-channel for all three drain call sites.

Measured A/B (Omega, `perf stat`, 12 s window, iperf3 TCP through TUN,
same harness for both binaries):

| syscall | reader-thread | reactor-fd | delta |
|---|---|---|---|
| ppoll | 4,544 | 0 | -100% (reader poll loop gone) |
| read | 29,439 | 23,513 | -20% |
| epoll_pwait | 20,282 | 23,831 | +17% (readiness moves into the reactor) |
| futex | 22,212 | 24,026 | +8% |
| sendmsg+sendmmsg | 8,954 | 8,713 | -3% |
| recvmmsg | 20,364 | 21,800 | +7% |
| write | 10,193 | 9,956 | -2% |
| **total** | **~116k** | **~98k** | **-16%** |

Throughput: 18.3 -> 17.5 Mbit/s (-4%, inside single-core noise on the
Neoverse-N1). Net: one OS thread and its entire synchronization surface
removed, ~16% fewer syscalls, same throughput.

Verification: `tun-e2e-netns.sh` PASS both directions, 0% loss, clean
teardown. The server-side reader thread intentionally remains: the server
runtime has its own event-loop ownership story and is a separate task.

Non-unix fallback: `TunReadSource` is an uninhabited enum off unix -
`Option<TunReadSource>` is always `None`, the select branch never fires,
and the reader-thread path stays the fallback (Wintun has no pollable fd).

## Server side: same migration, verified

The standalone server followed the same pattern: `ServerTunIngress`
(`src/implementations/server/tun_path.rs`) replaces the bare receiver with
`Fd(TunReadSource)` | `Channel { rx, pending }` | `Closed`. On unix the
server TUN fd sits in the reactor (`reactor_read_end`); the reader thread,
wave channel, and notify hop are skipped entirely. `wait_progress` merges
fd-readiness and channel-notify into one `select!` arm; the drain bound
stays 32 frames. No carrier gate exists server-side, so the fd drain has
no backlog leg - frames dispatch straight into the bounded downlink
queues.

Verified on Omega: `tun-e2e-netns.sh` PASS (5/5 both directions, 0% loss,
clean teardown incl. server crash/restart), server log confirms
"reactor-fd ingress (no reader thread)" for both generations.

`TunReadSource`/`TunReadEnd` moved to `quicfuscate::interface` so the
binary (`main::runtime`) and library (`implementations::server`) share the
same reactor-fd type; off unix the enum is uninhabited and every gated
select arm compiles away.
