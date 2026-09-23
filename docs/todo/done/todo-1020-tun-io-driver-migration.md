---
id: TODO-1020
title: Decide whether the standalone TUN client migrates to the io_driver runtime
severity: LOW
phase: L
priority: P3
status: DONE
created: 2026-09-21
depends_on: [TODO-1016]
---

# TODO-1020: Standalone TUN client -> io_driver migration decision

## Context

Carried over from TODO-1016 "Remaining work": the standalone client's
`select!` loop (`src/implementations/client/client.rs`) grew its own
scheduler - housekeeping tick, deadline waits, yield bookkeeping. The
`io_driver` runtime (`src/implementations/client/io_driver/`) already
exists as the deadline-driven, event-based carrier used elsewhere and
was identified during TODO-1015 as "the right carrier for the full
effect" of windowed reorder.

The gather-timer model (TODO-1016) removed the worst serialization
(~1 packet per wake), so this is no longer a throughput blocker - it
is a convergence decision: two scheduler implementations with
overlapping responsibility.

## Objective

Decide: migrate the standalone TUN path onto `io_driver` or document
why the bespoke loop stays. Deliverable is a written verdict with the
cost/benefit table - implementation TODO only if the verdict is
"migrate".

## Questions the study must answer

1. Does `io_driver` express everything the standalone loop needs:
   TUN-fd readiness, socket readiness, armed deadline waits
   (`next_send_deadline`), housekeeping cadence, signal/shutdown
   handling? List any missing primitive concretely.
2. What does the standalone loop gain: finer wake granularity than the
   housekeeping floor, unified deadline handling, less bespoke yield
   bookkeeping? Quantify against post-TODO-1016 behavior (drain epochs
   already emit batches; is the remaining gap scheduler-caused at
   all?).
3. **TUN-ingest backpressure profile** (added from TODO-1017 findings):
   Omega measured ~38-44% uplink loss at 60 M offered with reorder
   active - ~100% kernel TUN-queue drops (`qtun0 TX dropped`). The
   standalone path parks fd reads the moment `dgram_send_queue` (1024)
   backpressures (`drain_client_tun_uplink_fd` ->
   `tun_backpressure_frame`), while the loop keeps burning `conn.send`
   polls (~96% empty yields). Compare against io_driver's
   `enqueue_tun_datagram` (flush-before-sleep retry,
   `io_driver/runtime.rs` ~L608): does its ingest stop pulling the fd
   earlier/later, does its loop spin the same way under emission gaps,
   and does the measured rate ceiling (~3.4-3.7k pkt/s on Omega's
   single-core) change?
4. Migration cost: which code moves, what tests cover the loop today,
   what e2e coverage (`tun-e2e-netns.sh`) verifies parity.

## Acceptance

- Written verdict in this file (migrate / stay / partial - e.g. adopt
  only the deadline-wait primitive).
- If migrate: spawn a scoped implementation TODO with the mapped
  code moves and the parity test plan.
- If stay: the duplicated-responsibility rationale is recorded so the
  question does not get re-litigated every cycle.

## Verdict: STAY (2026-09-21)

Migrate neither the loop nor the primitives. The measured Omega gap is
a local defect in the standalone drain (early return on backpressure
leaves the AsyncFd readiness latched -> hot select spin), not an
architectural deficiency that `io_driver` solves. The one behavioral
advantage found (bounded backpressure retry) is adoptable in ~15
lines; see TODO-1021.

### Q1 - can io_driver express the standalone loop?

| Primitive | Standalone (`main/runtime/client.rs`) | io_driver (`io_driver/runtime.rs`) | Verdict |
|---|---|---|---|
| TUN-fd readiness | `AsyncFd` (`TunReadSource`) select arm, level-triggered via `try_io` | `AsyncFd<TunFdRef>` inside `wait_tun_idle` | parity |
| Socket readiness | `recv_connected_burst` select arm (recvmmsg + UDP_GRO) | `run_inbound` task: recv + `try_recv` batch drain, optional io_uring SQE path | parity (io_uring is io_driver-only) |
| Armed deadline waits | `client_housekeeping_delay`: min(`next_send_deadline`, 5 ms active / 250 ms idle), 1 ms floor | `wait_tun_idle`: `next_send_deadline` capped at 250 ms, **no floor**; `recv_timeout`: deadline capped at 200 ms, 1 ms floor | parity; outbound arm regresses (no floor -> `sleep(~0)` yield loop under emission gaps) |
| Housekeeping cadence | drives `begin_masque_tunnel`, `send_http3_request`, `open_http3_stream_post`, H3 downlink poll, kill-switch connected transition, DoH DNS proxy start, heartbeat probes, TUN MTU sync, `conn.update_state`, stats log | **absent** - io_driver loops are pure data-plane pumps on a prepared `ClientDataPlane`; lifecycle lives in `PreparedClientTransport` + subsystem tasks | missing primitive |
| Shutdown | `wait_shutdown_signal()` select arm -> graceful `conn.close` + flush | `AtomicBool` polled per iteration (250 ms cap) | expressible, weaker contract |
| Connection ownership | `QuicFuscateConnection` by value, zero locking | `Arc<parking_lot::Mutex<ClientDataPlane>>` - mutex per `send`/`recv_mut`/`send_tunnel_packet` | regression: lock on every hot-path call |
| Backpressure container | `tun_backpressure_frame: Option<(Vec<TunPacket>, usize)>` parked wave + cursor, FIFO | none - `enqueue_tun_datagram` blocks in a retry loop holding the frame | functionally equivalent |

### Q2 - gain vs loss

Gains: inbound/outbound task split (parallel only on multi-core;
Omega is single-core), io_uring dispatch, unified TUN+deadline wait.
Losses: a mutex on every hot-path connection call, no deadline floor
in `wait_tun_idle`, and one-datagram-per-wake emission on the idle arm
(`poll_connection_send`) vs the standalone's burst-limit flush - the
standalone is already the better shape for drain-epoch bursts
(TODO-1016). The bespoke yield bookkeeping the loop keeps
(backlog cursor, housekeeping reset, diagnostics) is small and
standalone-specific.

### Q3 - TUN-ingest backpressure profile

Both paths stop reading the TUN fd the moment `dgram_send_queue`
(1024) returns `DgramQueueFull`/`Backpressure` - the kernel queue then
overflows identically (`qtun0 TX dropped`). The difference is the
retry profile:

- **Standalone** (`drain_client_tun_uplink_fd`, `src/main/runtime.rs`
  ~L1230): `Backpressured` -> `return Ok(false)` *before any fd read*.
  The `AsyncFd` readiness stays latched (only an inner `WouldBlock`
  clears it), so the select arm resolves immediately every iteration:
  an unbounded hot spin, each iteration additionally running
  `flush_connected_outgoing` (>= 1 empty `conn.send` poll during
  emission gaps). This is the mechanism behind the observed
  `send_polls` ~27x `send_datagrams` and the CPU ceiling.
- **io_driver** (`enqueue_tun_datagram`, `io_driver/runtime.rs` ~L600):
  `Backpressure` -> `flush_outbound` (<=16-packet sendmmsg rounds)
  + `sleep(1 ms)` -> retry until accepted. The frame is never dropped,
  the fd is equally unread during the retry, but the cadence is
  bounded at ~1 kHz and every retry performs real emission work.

io_driver's retry is strictly better behaved, but the terminal
kernel-drop behavior at offered > capacity is identical. The measured
~3.4-3.7k pkt/s ceiling is **not** scheduler-caused: both schedulers
translate `next_send_deadline` into wake cadence and poll the same
`conn.send`; the ceiling is per-packet work (stealth/FEC/encode/send)
plus the standalone's spin overhead on one core. Migration ports the
defect shape - it does not remove it.

### Q4 - migration cost

- ~500 lines of select arms would split into outbound/inbound tasks
  plus a **new third control task** (or prepared-transport
  restructure) for the lifecycle duties listed above - none of which
  have an io_driver home.
- `QuicFuscateConnection` would move behind `ClientDataPlane`'s
  `Arc<Mutex>` (or io_driver would need generification) - invasive
  either way.
- Test coverage today: zero unit tests for the standalone drain
  (`src/main/` has no test module for it); io_driver has thin unit
  tests (config/stats/shutdown). Behavioral parity is owned by the
  `tun-e2e-*.sh` family, which exercises the standalone binary, and
  the Omega soak - a migrated path would need the full suite re-run
  plus parity diagnostics.
- Net: a same-defect port plus a mutex plus a third task, to gain a
  1 ms-bounded retry that the standalone can adopt locally.

### Stay rationale (do not re-litigate)

The two loops serve different contracts: the standalone loop is the
client **lifecycle orchestrator** (setup, kill switch, DNS, heartbeat,
diagnostics) that happens to pump data; io_driver is a pure data-plane
pump for an already-prepared circuit. Keeping both is not duplicated
scheduler responsibility - it is two different layers. The actionable
finding of this study is the park-path spin, tracked as TODO-1021.
