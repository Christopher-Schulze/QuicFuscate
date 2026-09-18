# TODO-972 - PathScheduler per-packet Vec allocs (latent multipath flaw)

Status: DONE (local; dormant code - no production caller exists yet)

## Problem

`PathScheduler::select_path` is designed to run once per outgoing packet on
the multipath send path, but it allocated on every call:

1. `path_manager.validated_path_ids()` collected `Vec<PathId>` - one alloc
   even for the single-path fast return, which is the common case.
2. `select_weighted_proportional` collected `Vec<(PathId, u64)>` - a second
   alloc per call.

The whole `qf-transport-path` crate is currently dormant: `PathManager`,
`PathScheduler`, and `validated_path_ids` have zero callers in `src/` (grep
verified). Multipath is not yet wired into the connection send path, so
this was a latent design flaw rather than a live regression - but it is
exactly the pattern that must not land when multipath is integrated.

## Fix

`select_path` now iterates `path_manager.paths()` (`&[PathState]`) directly:

- One validation pass counts validated paths and remembers the first id,
  replacing the collected `Vec` and the `is_empty`/`len() == 1` checks.
- RoundRobin keeps the single cursor-advance-then-modulo semantics, picking
  the nth validated entry via `filter().nth()`.
- LowestLatency scans validated entries once (identical strict `<` tie
  semantics: first validated wins ties).
- WeightedProportional sums `(cwnd as u64).max(1)` and walks the weighted
  buckets in the same pass structure as before; the unreachable fallback now
  returns `first_validated` (was `validated[0]` - identical value).

`validated_path_ids()` stays public and unchanged - it is still the right
API for callers that need a snapshot list; the scheduler just must not use
it per packet.

## Verification

- `cargo test -p qf-transport-path` - 27/27 (RR/LowestLatency/Weighted
  distribution tests cover the rewritten selection)
- `cargo clippy -p qf-transport-path --all-targets` - clean
- `cargo fmt --check` - clean
- Omega: not synced - dormant code, no runtime path affected; local proof
  sufficient until multipath integration.
