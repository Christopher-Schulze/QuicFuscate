---
id: TODO-1000
title: Fountain repair generation encodes into the pooled wire block
severity: LOW
phase: S
priority: P2
status: DONE
created: 2026-11-18
depends_on: []
---

# TODO-1000: Fountain Repair Generation Encodes Into the Pooled Wire Block

## Objective
The `Fountain` arm of `FecEncoderKind::generate_repair_packet` encoded the LT
symbol into the encoder's internal scratch and then copied it into a
`PooledBlock` via `copy_to_pooled_block` - one extra `max_symbol_len` memcpy
per repair packet. The GF8/GF16 encoders already accumulate directly into
the pooled wire block.

## Implementation
- New `LTEncoder::generate_symbol_into(symbol_id, out) -> Option<(usize,
  &[usize])>`: same degree selection and XOR accumulation as
  `generate_symbol`, writing into a caller buffer. Returns `None` when `out`
  is smaller than the encoded length; preserves the empty-encoder zero-fill
  semantics.
- `variants.rs` Fountain arm now allocates `data_block` first and encodes
  straight into it; `encoded_len` feeds `FecPacket::from_pooled_blocks`.
- `copy_to_pooled_block` retained - the receiver/decoder paths still use it.

## Acceptance
- New tests prove byte-identical output and identical index lists vs
  `generate_symbol` across multiple symbol ids, plus undersized-buffer
  rejection on both the populated and the empty-encoder path.
- `cargo test -p qf-fec`: 96/96 green; `cargo clippy -p qf-fec` clean.

## Deviations
None.
