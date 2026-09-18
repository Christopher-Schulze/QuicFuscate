# TODO-957 — `Frame::Ack.ranges`: inline `SmallVec` instead of a heap `Vec` per ACK

## Status
DONE

## Problem
Every ACK frame allocated one heap `Vec` in **each** direction:

- **Parse path**: `qf-transport-frames` built `Vec::with_capacity(num_blocks + 1)`
  per inbound ACK frame — for the overwhelmingly common single-block ACK a
  16-byte allocation that is dropped at the end of frame dispatch.
- **Emit path**: `PktNumSpace::peek_ack_at`/`take_ack_at` collected
  `ack_ranges.iter().map(...)` into a fresh `Vec` for every outbound ACK, on
  every packet number space that had a pending acknowledgment.

A busy connection emits roughly one ACK per two inbound packets, so both
directions paid `alloc + free` at line rate for a structure that almost
always holds a single `(u64, u64)` pair.

## Solution
- New shared alias `qf_transport_types::AckRanges =
  SmallVec<[(u64, u64); 8]>` — eight inline blocks (128 B) cover essentially
  all real ACK frames; loss-heavy frames spill to the heap transparently.
- `Frame::Ack.ranges: Vec<(u64, u64)>` → `AckRanges`.
- `peek_ack_at`/`take_ack_at`/`take_ack` return `Option<(u64, AckRanges)>`
  and collect into the inline buffer (also fixes the `type_complexity`
  lint via the alias).
- The frame parser constructs `AckRanges::with_capacity(...)` directly;
  `sort_by_key`, iteration, indexing and `&[T]` consumers work unchanged
  through `SmallVec`'s `Deref<Target=[T]>` — all existing call sites
  (`on_ack_received(&ranges)`, `acknowledge_late_stream_packets`,
  observer `on_ack`, `wire_len`/`to_bytes`) needed no signature changes.

`Frame` grows to ~170 B — still a small stack enum produced once per frame
iteration; in exchange both directions allocate zero bytes for ≤8 blocks.

## Verification
- `cargo test -p qf-transport-types -p qf-transport-frames
  -p qf-transport-pn`: 21 + 27 + 43 green (roundtrip, malformed-range
  rejection, ACK decision paths).
- `cargo test -p quicfuscate transport::connection::tests`: 139/139.
- `cargo check --workspace --all-targets`, clippy, `cargo fmt --check`:
  clean.
- Omega: native check + clippy + tests all green on Linux.
