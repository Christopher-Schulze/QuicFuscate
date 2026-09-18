# TODO-980 - FEC transport feedback dead in production: callbacks lost on recovery rebuild

## Symptom

On Omega (`tun-e2e-fec-netem-adversity.sh` and a manual 20% `tc netem` probe):

- `quicfuscate_fec_active_connections_total` = 1 (telemetry-enabled instance exists)
- `quicfuscate_fec_observed_packets_total` = 0
- `quicfuscate_fec_observed_lost_packets_total` = 0
- `quicfuscate_fec_repair_packets_sent_total` = 0
- `quicfuscate_fec_mode_switches_total` = 0
- Tunnel ping loss ~40% under 20% underlay loss both directions (~36% compound = raw pass-through, zero protection)

Adaptive FEC never engaged on a live connection despite heavy loss.

## Root cause

`QuicFuscateConnection::new` (`src/core/connection.rs:601`) calls
`conn.set_environment_snapshot(...)` on every connection before enabling TLS.
`set_environment_snapshot` (`src/transport/connection/lifecycle.rs`) rebuilds
`self.recovery` via `configured_recovery_with_snapshot` — a brand-new `Recovery`
with a brand-new congestion controller whose `fec_on_sent`/`fec_on_lost` fields
are `None`. The callbacks installed at construction
(`install_recovery_fec_callbacks`, `lifecycle.rs:309`) are silently dropped.

Consequences:

- `fec_cb_sent_packets` / `fec_cb_lost_packets` stay 0 forever.
- `fec_acked_packets` (a `Connection` field, not in `Recovery`) still increments,
  so `apply_fec_transport_feedback` does run — but always with `sent=0, lost=0`.
- `observed_packets` only counts the sent delta -> stays 0.
- `loss_estimator.report_actual_observation(acked, 0)` sees only clean ACKs ->
  smoothed loss stays ~0 -> `update_mode` keeps `FecMode::Zero` -> no wire
  framing, no repairs, no switches.

The version-negotiation restart path (`tls_and_crypto.rs:405-414`) already
re-installs the callbacks after its own recovery rebuild; the environment
snapshot path was missing the same reinstall.

## Fix

`set_environment_snapshot` now calls `self.install_recovery_fec_callbacks()`
after assigning the rebuilt recovery. The replacement happens pre-TLS /
pre-traffic (`debug_assert!(tls_provider.is_none())`, `bytes_in_flight == 0`),
so reinstalling is safe and mirrors the VN-restart contract.

## Proof

- New regression test
  `fec_callbacks_survive_environment_snapshot_replacement`
  (`src/transport/connection/tests/recovery_and_scheduling.rs`) fails without
  the fix (`sent_packets` stays 0 after `set_environment_snapshot`) and passes
  with it.
- Full lib suite green.
- Omega re-verified on the release binary: `tun-e2e-fec-netem-adversity.sh`
  25/25 PASS with live feedback — e.g. `recovery-lossy: observed=126 lost=10
  switches=1` (14% tunnel loss under 20% injection while the controller was
  still ramping) and `recovery-recovered: observed=126 lost=12 repairs=17
  switches=2`, tunnel loss back to 0%. Direct 20% netem probe: server reached
  `mode=extreme` (27.9% observed loss), client `mode=strong` (29.7%), both via
  `switch_reason=adaptive`.
