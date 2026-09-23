---
id: TODO-949
title: TUN outbound loop: event-driven idle wait instead of 100us polling
status: DONE
created: 2026-09-18
---

# TODO-949 - TUN outbound loop: event-driven idle wait instead of 100us polling

## Status
DONE

## Problem
`run_outbound` polled the nonblocking TUN fd on a fixed `poll_interval_us = 100`
cycle whenever no packet was pending. With tokio's ~1 ms timer granularity the
loop still woke roughly 1,000 times per second while completely idle - every
wakeup locks the connection, attempts `poll_connection_send`, and pays syscall
overhead. On a phone/router-class CPU this is continuous battery and core burn
for zero throughput.

## Solution
Register the TUN descriptor with the tokio reactor once per `run_outbound`
(`AsyncFd` over a borrowed `TunFdRef` wrapper - the fd stays owned by the
`TunDevice` backend). Both idle arms (empty read and `WouldBlock`/`Interrupted`)
now call `wait_tun_idle`, which `select!`s on:

- `async_fd.readable()` - wakes instantly when uplink traffic arrives
- `sleep(remaining)` - the connection's own `next_send_deadline()` merged
  (pacing/stealth release, recovery/PTO, traffic-analysis), so ACK/handshake/
  keepalive emission keeps its timing without polling
- bounded to 250 ms so the `shutdown` flag stays responsive
- `clear_ready()` is called only in the WouldBlock path per the tokio
  readiness contract; a packet landing between read and clear is still picked
  up on the next loop's read-first pass

If the backend exposes no fd (`tun_raw_fd` -> `None`), the previous fixed-sleep
fallback is kept unchanged.

## Verification
- `cargo check --lib` clean locally and natively on Omega (aarch64/Linux).
- `cargo clippy --lib --all-targets` clean; `cargo fmt` clean.
- io_driver suite: 20/20 green on Omega.

## Files
- `src/interface.rs` - `TunInterface::tun_raw_fd()` (unix).
- `src/implementations/client/io_driver/runtime.rs` - `TunFdRef`,
  `TunReadable`, `wait_tun_idle`, both idle call sites.
