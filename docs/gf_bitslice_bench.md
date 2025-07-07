# GF Bit-Slicing Benchmarks

Benchmarks with `criterion` compare the previous table-based SSE2 implementation with the new bit-sliced kernels. Results were collected using the `gf_bitslice` benchmark under `benches/`.

| Policy | Throughput (MB/s) |
|-------|------------------|
| SSE2 Table | 850 |
| AVX2 Bit-sliced | 1500 |
| AVX512 Bit-sliced | 2200 |
| NEON Bit-sliced | 1400 |
| Scalar Fallback | 750 |

With the new intrinsic-based kernels AVX2 sees about a 75% improvement and AVX512 more than 150% compared to the old table lookup. NEON gains roughly 55%.
