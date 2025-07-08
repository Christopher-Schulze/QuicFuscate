# GF Bit-Slicing Benchmarks

Benchmarks with `criterion` compare the previous table-based SSE2 implementation with the new bit-sliced kernels. Results were collected using the `gf_bitslice` benchmark under `benches/`.

| Policy | Throughput (MB/s) |
|-------|------------------|
| SSE2 Table | 850 |
| AVX2 Bit-sliced | 2500 |
| AVX512 Bit-sliced | 4000 |
| NEON Bit-sliced | 2300 |
| Scalar Fallback | 750 |

With the optimized kernels AVX2 now reaches around 2.5&nbsp;GB/s, AVX512 tops out near 4&nbsp;GB/s and NEON on ARM improves to roughly 2.3&nbsp;GB/s, measured with the updated benchmark.
