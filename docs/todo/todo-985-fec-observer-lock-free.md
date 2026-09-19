# TODO-985 - FecObserver RwLock write storm starves the telemetry tick (82% server CPU)

## Symptom

Symbolized `perf` on Omega (scenario i, 5% netem, ~9.3 Gbit/s inner traffic)
showed `FecObserver::compute_streaming_interval` at **82% of server CPU**,
plus `__aarch64_swp4_acq` (RwLock atomics) at 7.7% and `log::Level::fmt`
noise. The tick itself is trivial arithmetic — the cost was lock starvation.

## Root cause

`FecObserver` kept its EWMA/counter state behind `RwLock<FecObserverState>`.
`on_ack` took `state.write()` **once per emitted ACK frame**; at multi-Gbit/s
packet rates that is a write storm. The streaming-interval tick's
`state.read()` then spent its time retrying against writers (fair queuing on
aarch64 shows up as `swp4_acq` spins), turning a nanoseconds-long read into
the dominant CPU consumer.

## Fix

`FecObserverState` converted to plain atomics (`AtomicU64`/`AtomicU32`,
`f64` as bits). `on_ack` is the single writer in the connection context, so
the EWMA read-modify-write race is benign; all fields are scalar. `RwLock`
removed entirely — no read or write can starve.

Commit `8a690a7` (`fec: make FecObserver telemetry lock-free`).

## Verification

- qf-fec suite green locally; fmt/clippy clean.
- Omega scenario g (release binary with the fix, cpu-clock profile):
  **67.9 Mbit/s PASS** vs 46.3 Mbit/s immediately after the BBR3 fix on the
  same single-core testbed — the freed observer CPU feeds the dataplane.
  perf record + flamegraph PASS.

## Remaining

- Re-run a symbolized profile on multi-core hardware to quantify the next
  hot spots (aarch64 single-core testbed is contention-bounded).
