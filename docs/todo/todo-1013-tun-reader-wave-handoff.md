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
