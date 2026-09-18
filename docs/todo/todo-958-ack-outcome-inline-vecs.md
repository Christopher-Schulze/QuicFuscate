# TODO-958 — `AckOutcome`: inline `SmallVec` for `newly_acked`/`lost`

## Status
DONE

## Problem
`AckOutcome` is produced by `Recovery::on_ack_received` once per inbound
ACK frame and returned by value — its vectors cannot live in the recovery
scratch (ownership escapes). Per ACK:

- `newly_acked: Vec<(u64, usize)>` allocated on the first push — this
  happens on **every** ACK that acknowledges packets (the common case).
- `lost: Vec<(u64, usize)>` allocated under any loss burst.
- `crypto_acked`/`crypto_lost` allocated only for Initial/Handshake spaces
  (cold — left as `Vec`, no steady-state cost).

So a connection still paid one guaranteed heap alloc + free per ACK after
TODO-956 eliminated the internal scratch allocations.

## Solution
`newly_acked` and `lost` became `SmallVec<[(u64, usize); 8]>`:

- ≤8 entries stay inline — covers the typical per-ACK packet count under
  the ACK-every-2 policy; bulk acknowledgments spill transparently.
- `crypto_*` fields remain `Vec` (handshake spaces only — `Vec::new()`
  never allocates until first push, so there is no steady-state cost).
- All consumers iterate/`len`/`is_empty` through `Deref<Target=[T]>` —
  `apply_ack_outcome`, benches and tests needed no call-site changes.
- Test assertions comparing against `vec![...]` gained `.as_slice()`
  (smallvec implements slice equality, not `PartialEq<Vec>`).

`AckOutcome` grows by ~256 B — returned by value once per ACK, still far
cheaper than one or two alloc/free cycles.

## Verification
- `cargo test -p qf-transport-recovery`: 50/50.
- `cargo test -p quicfuscate transport::connection::tests`: 139/139.
- `cargo check --workspace --all-targets`, clippy, `cargo fmt --check`:
  clean.
- Omega: native check + clippy + recovery tests green on Linux.
