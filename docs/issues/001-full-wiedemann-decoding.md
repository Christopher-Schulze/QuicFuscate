# Issue: Complete Wiedemann Decoding

**Status: closed – implemented in latest decoder overhaul.**

## Description
The current FEC decoder implements a simplified Wiedemann algorithm. After generating the Lanczos sequence and applying Berlekamp–Massey it falls back to Gaussian elimination. According to `docs/PLAN.txt` the decoder should use a full Wiedemann approach with block-Lanczos iteration and block recursive inversion for large windows.

## Tasks
- [x] Implement block-Lanczos iteration for sequence generation.
- [x] Integrate Berlekamp–Massey result to solve the linear system without Gaussian fallback.
- [x] Add CPU-cache aware block-recursive matrix inversion as described in PLAN.txt.
- [x] Extend tests in `src/fec/decoder.rs` to cover large window sizes (>256).

## Planned Commits
1. **refactor decoder structure** – introduce dedicated modules for Wiedemann state and matrix operations.
2. **implement block-Lanczos and polynomial solver** – produce minimal polynomial and recover solution vectors.
3. **add block-recursive inversion** – optimize for cache locality and parallelism.
4. **update tests** – verify recovery for windows 512 and 1024.
