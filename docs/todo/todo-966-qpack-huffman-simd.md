# TODO-966 - QPACK Huffman encode through SIMD dispatch

## Status
DONE

## Problem
`src/transport/h3/qpack.rs::huff_encode_into` called
`qf_simd::qpack::huff_encode_into` - the pure scalar bit-accumulator -
for every encoded string literal in every QPACK header block. The crate
already ships `encode_huff_into`, a drop-in dispatcher with identical
signature `(input, output) -> usize` that selects:

- `x86::qpack_encode_avx2` on x86_64 with AVX2
- `arm::qpack_encode_neon` on aarch64 with NEON (baseline)
- `huff_encode_into` scalar fallback otherwise

The NEON kernel expands 8 input bytes per iteration into u32 lanes for
table lookup and accumulates codes in a u128 accumulator (vs u64 scalar),
halving flush frequency. Semantics are identical: same `written` return on
full output, same bit order, same tail handling - verified by reading both
implementations and by the crate's roundtrip tests.

## Solution
One-word rewire in the production wrapper:

```rust
qf_simd::qpack::encode_huff_into(input, output)
```

Decode path deliberately unchanged: `huff_decode_into` returns
`Result<usize, HuffmanError>` which distinguishes `InvalidEncoding` (maps
to `Error::QpackDecompressionFailed`) from `BufferTooShort`. The
`qf_simd::h3::qpack_decode` dispatcher returns bare `usize` and cannot
surface invalid-encoding failures - rewiring it would silently accept
malformed Huffman input, so the scalar trie decoder stays.

Also audited and rejected during the same SIMD-wiring sweep:

- `x86_header::validate_header_*` - 1-byte mask check mislabeled as a SIMD
  kernel; the real header parse path is unaffected.
- `string::compare` - redundant to `a == b` (slice equality already lowers
  to memcmp/bcmp).
- `bitstream::pack_bits`/`unpack_bits` - no production caller needs raw
  bit-packing; Huffman uses its own accumulator.
- `h3::qpack_encode`/`qpack_decode` - harness-facing aliases; the real
  paths use `qpack::huff_*` / `qpack::encode_huff_into`.

## Verification
- `cargo test -p qf-simd` - 61/61 (NEON kernel executes natively on
  aarch64; the dispatched path, not the fallback)
- `cargo test -p quicfuscate h3` - 115 passed; `qpack` - 22 passed
- `cargo clippy -p quicfuscate --all-targets` - clean
- `cargo fmt --check` - clean
- Omega (aarch64 Linux): qf-simd 61/61, qpack 22/22 - NEON dispatch
  verified on the production target
