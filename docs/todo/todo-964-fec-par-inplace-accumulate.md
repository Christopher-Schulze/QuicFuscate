# TODO-964 - FEC repair encoders: in-place `par_chunks_mut` instead of scratch vecs + merge

## Status
DONE

## Problem
All three GF repair encoders (GF8/GF4/GF16) already parallelized large
payloads (`max_len >= PAR_THRESHOLD*4`, i.e. >32 KiB, with `wlen >= 8`), but
the parallel path built `vec![0u8; chunk]` scratch buffers per 16 KiB chunk,
collected them into a `Vec<(usize, Vec<u8>)>`, then merged every chunk back
into `out` via `xor_blocks` - one alloc per chunk plus a full-payload merge
pass per repair generation.

## Solution
`gf_mul_scalar_slice` / `gf4_mul_xor` / `gf16_mul_scalar_slice_padded` all
XOR-accumulate into their destination, and `out[..max_len]` is already
zeroed. Since the chunks are disjoint and XOR is commutative, the workers
can accumulate **directly into `out`**:

```rust
out[..max_len]
    .par_chunks_mut(chunk)
    .enumerate()
    .for_each(|(ci, acc)| { /* scalar kernels write into acc */ });
```

- GF8 + GF4: `&mut acc[..len]` replaces the scratch vec.
- GF16: `chunk = 16384` is a multiple of 2, so every `par_chunks_mut` bound
  stays u16-aligned - the old manual even-boundary fixup is inherent now.
- `parts` collection, per-chunk `vec!`, and the `xor_blocks` merge pass are
  gone; `FEC_SIMD_ENCODE` telemetry is still incremented once per chunk.

## Verification
- New test `codecs::par_path_tests::gf8_parallel_repair_matches_scalar_reference`
  feeds 8x36 KiB sources (forces the rayon branch) and asserts the repair
  payload equals the scalar `gf_mul_table` XOR-of-products reference -
  byte-identical.
- `cargo test -p qf-fec --features rust-tests`: 85/85 local.
- `cargo check -p qf-fec --all-targets`, clippy, `cargo fmt --check`: clean.
- Omega (aarch64): native 85/85 + clippy - green.
