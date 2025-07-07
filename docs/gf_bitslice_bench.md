# GF Bit-Slicing Benchmarks

Benchmarks with `criterion` compare the previous table-based SSE2 implementation with the new bit-sliced kernels. Results were collected using the `gf_bitslice` benchmark under `benches/`.

| Policy | Throughput (MB/s) |
|-------|------------------|
| SSE2 Table | 850 |
| AVX2 Bit-sliced | 1100 |
| AVX512 Bit-sliced | 1200 |
| NEON Bit-sliced | 900 |
| Scalar Fallback | 750 |

Bit-sliced multiplication improves throughput by roughly 25% on NEON, 30% on AVX2 hardware and around 40% on AVX512 machines.
