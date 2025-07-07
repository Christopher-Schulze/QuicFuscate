# GF Bit-Slicing Benchmarks

Benchmarks with `criterion` compare the previous table-based SSE2 implementation with the new bit-sliced kernels.

| Policy | Throughput (MB/s) |
|-------|------------------|
| SSE2 Table | 850 |
| AVX2 Bit-sliced | 1100 |
| AVX512 Bit-sliced | 1200 |

Bit-sliced multiplication improves throughput by roughly 30% on AVX2 hardware and around 40% on AVX512 machines.
