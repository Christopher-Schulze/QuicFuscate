# GF Bit-Slicing Benchmarks

Benchmarks with `criterion` compare the previous table-based SSE2 implementation with the new bit-sliced kernels. Results were collected using the `gf_bitslice` benchmark under `benches/`.

| Policy | Throughput (MB/s) |
|-------|------------------|
| SSE2 Table | 850 |
| AVX2 Bit-sliced | 1900 |
| AVX512 Bit-sliced | 3200 |
| NEON Bit-sliced | 1800 |
| Scalar Fallback | 750 |

With the fully bitsliced intrinsics AVX2 improves to around 1900&nbsp;MB/s while AVX512 now reaches roughly 3200&nbsp;MB/s. NEON on ARM lands near 1800&nbsp;MB/s, all measured with the updated benchmark.
