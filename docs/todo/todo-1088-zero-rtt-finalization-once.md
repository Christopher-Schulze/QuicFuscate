---
id: TODO-1088
title: Finalize 0-RTT state exactly once per handshake
severity: MED
phase: M
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1031]
---

# TODO-1088: One-time 0-RTT finalization

## Why and evidence

`poll_tls_and_validate_versions` in
`src/transport/connection/lifecycle/tls_and_crypto.rs` calls
`finish_zero_rtt` whenever the TLS provider returns `Some(accepted)`.
`src/qftls/rustls_provider.rs` exposes the resolved acceptance state on later
polls as well. `finish_zero_rtt` in `lifecycle.rs` clears packet state,
scans every stream transmission, and takes a crypto write lock each time.
The repeated state transition is unnecessary on a hot TLS polling path and
could obscure accounting or later error handling. On rejection,
`finish_zero_rtt(false)` also calls
`recovery.discard_space(PacketSpace::Application)` when any early packet was
sent. That space is shared with 1-RTT; the current tests do not construct a
mixed in-flight 0-RTT/1-RTT recovery state at the rejection boundary, so
preservation of unrelated 1-RTT accounting is not proven.

## Target contract

- Represent early-data resolution as a one-way state transition:
  `Pending -> Accepted` or `Pending -> Rejected`, at most once per handshake.
  A repeated identical provider observation is a no-op; a contradictory
  observation is a typed internal error, never a second transition.
- On acceptance, preserve correctly tracked early transmissions. On
  rejection, retransmit the admitted replay-safe streams exactly once,
  remove only 0-RTT packet accounting without discarding any live 1-RTT
  packet in the shared Application space, clear 0-RTT keys exactly once, and never
  promote H3/MASQUE/TUN/DATAGRAM data into early data.
- Keep established handshake and reconnect semantics unchanged; measure
  avoided scans/locks on the normal polling path before claiming a gain.

## Implementation and proof

- [ ] Inspect the TLS provider's acceptance return contract and all callers
      of `finish_zero_rtt` before adding a state owner.
- [ ] Gate the transition at the connection lifecycle boundary with one
      explicit state field or existing equivalent. Do not duplicate provider
      state unnecessarily.
- [ ] Test two or more polls after acceptance and rejection, conflicting
      resolution, mixed 0-RTT/1-RTT packet accounting, retransmission
      accounting, key erasure, and no early-data admission for forbidden
      stream classes.
- [ ] Bench or count stream scans/crypto write locks across repeated polls;
      document the measured delta and update TODO-1031 if its claim changes.

## Acceptance

- Exactly one finalization per handshake in accepted and rejected cases;
  subsequent polls perform zero stream-wide scans and zero 0-RTT key clears.
- Existing 0-RTT behavior and real transport tests remain green; no early
  application data is lost, duplicated, or admitted outside the allowlist;
  zero already-sent 1-RTT packets are discarded by 0-RTT rejection.
