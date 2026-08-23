# TODO-905: Bound PTO backoff for nested circuit hops

Renumbered from the collided "TODO-895" used in commits `22b6198`/`bfa920e`;
number 895 already belonged to the archived AesBlock hot-loop task.

## Why

Under netem impairment (1% loss, 2% reorder, 12ms delay, 4ms jitter) the
impaired 3-hop MASQUE circuit proof failed its TCP throughput probe and had
never passed in CI. Diagnosis on 2026-08-23 attributed this to a cumulative
PTO cascade: every stacked circuit hop owns an independent RFC 9002 recovery
instance, the per-hop backoff exponent grows without a practical ceiling
(2^16), and the compounded probe gaps stall the underlay long enough that
tunneled TCP connects time out. Underlay captures showed the exponential
inter-packet gap signature (1s -> 2s -> 3s -> 5s).

## Acceptance

- Recovery exposes a bounded PTO backoff exponent ceiling with the RFC default
  (16) preserved for ordinary single connections.
- Multi-hop circuit connections bound the exponent at 2^3.
- qf-transport-recovery regressions prove cap-bounding, clamping, and the
  unchanged RFC default ceiling.
- Impaired 3-hop netem proof passes on the native Linux bench.
- Unimpaired 3-hop proof shows no regression.

## Verified Evidence

- `crates/qf-transport-recovery/src/lib.rs`: `K_PTO_BACKOFF_CAP_DEFAULT = 16`,
  `Recovery::set_pto_backoff_cap` (clamped 1..=16), both PTO deadline sites
  honor `pto_backoff_cap`.
- `src/transport/config.rs`: `pto_backoff_cap` field + validated setter.
- `src/transport/connection/lifecycle.rs`: recovery construction applies the
  configured ceiling.
- `src/implementations/client/connection.rs`:
  `NESTED_CIRCUIT_PTO_BACKOFF_CAP = 3` applied when `hop_count > 1`.
- Tests: qf-transport-recovery 47/47 (`pto_backoff_cap_bounds_deadline_growth`,
  `pto_backoff_cap_is_clamped_to_valid_range`,
  `default_backoff_keeps_rfc_ceiling`); root lib 1717/1717; strict rust-tests
  Clippy; fmt clean.
- Omega (native Linux, ARM64, release build at `9edf00c`):
  - Impaired 3-hop PASS (first time): retained ratio 0.4104 >= 0.40,
    max RTT 377.865ms <= 500, max jitter 82.892ms <= 150, tunnel loss within
    the 10% bound, zero owned residue.
  - Unimpaired 3-hop PASS: retained ratio 0.9891, 0% loss, no regression.

## Notes

- Single-connection transports keep the RFC-style default ceiling; the tighter
  bound is scoped to nested circuits where recovery owners stack.
- Adjacent finding (not in scope): `claim_firewall_ownership` hard-fails with
  "durable firewall identity has a stale owner; explicit stale recovery is
  required" when a previous bench run left a dead-PID ownership record while
  the nft resource is absent; the bench recovered by deleting
  `/var/run/quicfuscate/routing/firewall-owner.json`. CI lanes are unaffected
  (fresh runners). A future task may automate dead-owner + absent-resource
  recovery on that path.

## Deviations

None.
