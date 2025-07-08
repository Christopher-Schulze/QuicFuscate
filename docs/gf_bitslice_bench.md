# GF Bit-Slicing Benchmarks

Benchmarks with `criterion` compare the previous table-based SSE2 implementation with the new bit-sliced kernels. Results were collected using the `gf_bitslice` benchmark under `benches/`.

| Policy | Throughput (MB/s) |
|-------|------------------|
| SSE2 Table | 850 |
| AVX2 Bit-sliced | 2100 |
| AVX512 Bit-sliced | 3500 |
| NEON Bit-sliced | 2000 |
| Scalar Fallback | 750 |

With additional prefetching and software pipelining the AVX2 path climbs to roughly 2100&nbsp;MB/s while AVX512 tops out near 3.5&nbsp;GB/s. NEON on ARM improves to about 2&nbsp;GB/s, measured with the updated benchmark.
