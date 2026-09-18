# TODO-967 - Fountain decoder: stale-tolerant symbol queues

## Status
DONE

## Problem
`LTDecoder` kept two FIFO queues whose membership truth lives elsewhere:

- `symbol_order` - eviction FIFO; `received_symbols` is the truth.
- `degree_one_queue` - peel worklist; `queued_symbol_ids` is the truth.

Every `remove_symbol_state` (eviction *and* every degree-1->0 propagation
completion) ran `symbol_order.retain(...)`, and every
`remove_queued_symbol` ran `degree_one_queue.retain(...)` - O(queue) scans
per removal. With the admission limit `max_symbols` up to
`MAX_FOUNTAIN_SOURCE_SYMBOLS` (12 288) a full decode window could spend
milliseconds per burst on queue compaction alone.

Both consumers already tolerate stale entries: `evict_oldest_symbol`
pops and re-checks `received_symbols`, and `belief_propagation_step`
re-validates via `symbol_degrees`/`queued_symbol_ids`. So removals never
needed eager queue cleanup at all.

## Solution
Stale-parked entries + two stale counters + bounded compaction:

- `remove_symbol_state` / `remove_queued_symbol` now increment
  `symbol_order_stale` / `degree_one_stale` instead of retaining.
- Pops discard stale entries for free and decrement the counter
  (`evict_oldest_symbol` on `!contains_key`, `belief_propagation_step`
  on `!queued_symbol_ids.remove`).
- `compact_*` rebuilds a queue via `retain` only when stale entries
  dominate (`stale * 2 >= len && len >= 64`) - amortized O(1) removal,
  queue size bounded to <= 2x live entries.
- `enqueue_degree_one` compacts before its `max_queue_len` check so the
  length heuristic isn't inflated by parked entries.

Semantics unchanged: membership decisions still go through
`received_symbols`/`queued_symbol_ids`; only the physical queue cleanup
became lazy.

## Verification
- `cargo test -p qf-fec` - 85/85 local (aarch64 macOS)
- `cargo clippy -p qf-fec --all-targets` - clean
- `cargo fmt --check` - clean
- Omega (aarch64 Linux): `cargo test -p qf-fec` - 85/85
