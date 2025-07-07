# Issue: SIMD Bit-Sliced GF Arithmetic

## Description
The finite-field implementation in `src/fec/gf_tables.rs` performs multiplication using tables and basic SIMD intrinsics. PLAN.txt lists advanced optimizations such as bit-slicing with NEON/AVX512 and prefetch-based pipelining which are not yet implemented.

## Tasks
- [ ] Implement bit-sliced GF(2^8) multiplication routines for AVX2/AVX512 and NEON.
- [ ] Add prefetch instructions and software pipelining to hide memory latency when generating coefficients.
- [ ] Provide feature detection and dispatch logic in `optimize` module to select the new code paths.
- [ ] Benchmark against the existing table-based implementation and document the results.

## Planned Commits
1. **simd bitslice kernels** – add new assembly or intrinsics based multiply functions.
2. **dispatch hooks** – update `gf_mul` and friends to call the optimized kernels.
3. **pipelining tweaks** – insert prefetch and loop unrolling in encoder/decoder.
4. **benchmarks** – add criterion benchmarks under `benches/` and update docs with performance numbers.
