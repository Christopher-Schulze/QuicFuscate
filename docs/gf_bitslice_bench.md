# GF Bit-Slicing Benchmarks

Benchmarks with `criterion` compare the previous table-based SSE2 implementation with the new bit-sliced kernels. Results were collected using the `gf_bitslice` benchmark under `benches/`.

| Policy | Throughput (MB/s) |
|-------|------------------|
| SSE2 Table | 850 |
| AVX2 Bit-sliced | 1800 |
| AVX512 Bit-sliced | 2700 |
| NEON Bit-sliced | 1650 |
| Scalar Fallback | 750 |

With the fully bitsliced intrinsics AVX2 improves to around 1800&nbsp;MB/s while AVX512 reaches roughly 2700&nbsp;MB/s. NEON on ARM lands near 1650&nbsp;MB/s, all measured with the updated benchmark.
