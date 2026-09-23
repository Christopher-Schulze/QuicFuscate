---
id: TODO-968
title: Fountain propagation through a source-index reverse map
status: DONE
created: 2026-09-18
---

# TODO-968 - Fountain propagation through a source-index reverse map

## Status
DONE

## Problem
`LTDecoder::propagate_decoded_symbol` iterated **every** retained
`symbol_degrees` entry per decoded source symbol and tested
`indices.contains(&decoded_idx)` - O(retained_symbols x avg_degree) per
propagation step. For a window holding S encoded symbols and D decodes the
peeling loop paid O(D x S x deg): trivial at k <= 256 (~us) but quadratic at
the `MAX_FOUNTAIN_SOURCE_SYMBOLS` (12 288) admission limit, where a full
window can hold ~11-13k symbols.

## Solution
Added `adjacency: Vec<Vec<u64>>` - a reverse index where
`adjacency[source_idx]` lists the retained encoded symbols referencing
`source_idx`. Maintained at exactly two places:

- `add_encoded_symbol_inner`: pushes `symbol_id` into `adjacency[idx]` for
  each validated index (the only `symbol_degrees.insert` site).
- `remove_symbol_state`: `swap_remove`s `symbol_id` from `adjacency[idx]`
  for each remaining index (the only `symbol_degrees.remove` site).

Propagation now iterates `adjacency[decoded_idx]` directly - only symbols
actually affected, O(adj_len) instead of O(S x deg). After the update
sweep the bucket is `clear()`ed: every referencing symbol dropped the
index from its degree set, so the bucket is spent.

Memory cost: `k` Vec headers (~24 B each -> ~300 KB at k = 12 288, ~6 KB at
k = 256) plus one u64 per retained (symbol, index) pair - bounded by the
existing admission limits.

## Correctness notes
- `propagation_work` now counts real updates instead of scan iterations.
  The `max_propagation_work` budget stays a hard cap; it became strictly
  *more* permissive (bounded work is now XOR updates, not wasted scans) -
  the DoS bound on total propagation work is preserved.
- Budget-exhaustion `break` leaves unprocessed ids in
  `adjacency[decoded_idx]`; the unconditional `clear()` discards them.
  Their degree lists still contain `decoded_idx` (never propagated, same
  as before - there is no retry path) and `remove_symbol_state`'s
  `position` lookup tolerates missing adjacency entries.
- `insert_symbol` runs before adjacency mutation, so an eviction during
  insertion cleans the *evicted* symbol's buckets only; the new symbol's
  entries don't exist yet and can't go stale.
- `belief_propagation_step`'s direct `received_symbols.remove` still
  leaves `symbol_degrees` in place until propagation's `became_empty`
  path calls `remove_symbol_state`, which now also cleans adjacency - the
  mirror invariant (`symbol_degrees` <=> `adjacency`) holds at every public
  boundary.

## Verification
- `cargo test -p qf-fec` - 85/85 (local, aarch64 macOS)
- `cargo clippy -p qf-fec --all-targets` - clean
- `cargo fmt --check` - clean
- Omega (aarch64 Linux): `cargo test -p qf-fec` - 85/85
