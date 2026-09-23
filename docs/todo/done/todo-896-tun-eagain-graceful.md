---
id: TODO-896
title: Graceful TUN EAGAIN handling
severity: HIGH
phase: S
priority: P0
status: DONE
created: 2026-08-21
depends_on: []
---

# TODO-896: Graceful TUN EAGAIN Handling

## Objective
Make TUN `WouldBlock` on non-blocking fd not kill the tunnel. Catch `EAGAIN` and queue to bounded pending with `AsyncFd` writability poll, reusing existing `PendingTunDownlinks` pattern.

## Verified Evidence
- `src/implementations/server/live_auth.rs:1290-1301` `if let Err(e) = tun.write(data) { record_live_tun_fault }` - WouldBlock treated as hard fault, server loop would break.
- `src/implementations/client/io_driver/runtime.rs:970-977` same for client watchdog disconnect.
- Both TUN fds are `O_NONBLOCK` (verified via `tun_path.rs`).

## Acceptance
- `tun.write` `WouldBlock` does not trigger `DataPlaneFault::TunWrite` or disconnect; instead enqueues to bounded `VecDeque` (cap 256) and wakes via `AsyncFd::writable()`.
- Burst test: 10k pps burst with artificially small TUN ring does not disconnect.
- Existing `PendingTunDownlinks` tests still green.

## Out of Scope
- No TUN MTU change.

## Deviations
None.
