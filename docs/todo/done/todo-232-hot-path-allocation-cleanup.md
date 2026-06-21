# TODO-232: Hot Path Allocation and Init Redundancy

## Severity: MEDIUM

## Problem

Three allocation/initialization issues in performance-critical paths:

### 1. Vec allocation in generate_fake_crypto_frame
`src/stealth.rs:786` creates `let mut frame = Vec::new()` on every call. This function is called from `stealth_padding()` in the TLS cover traffic hot path. Each call allocates and grows a Vec dynamically.

### 2. rand::thread_rng() re-creation at every TLS cover frame
`src/stealth.rs:792` creates `let mut rng = rand::thread_rng()` on every call to `generate_fake_crypto_frame()`. While `thread_rng()` is internally cached per-thread, the function call overhead and TLS lookup are unnecessary in a tight loop.

### 3. matrix_multiply_accumulate double initialization
`src/fec.rs:363-366` and `461-464` both do:
```rust
row.resize(n, 0);
row.fill(0);
```
The `resize(n, 0)` already zero-fills new elements, then `fill(0)` redundantly zeroes everything again. This pattern appears in both the scalar and SIMD matrix multiply variants.

## Fix

### Vec allocation
1. Pre-allocate a reusable buffer in the caller or accept a `&mut Vec<u8>` parameter
2. Or use `Vec::with_capacity(estimated_size)` at minimum

### RNG
3. Accept `rng: &mut impl Rng` as parameter instead of creating per-call
4. Let the caller maintain the RNG instance

### Double init
5. Remove the redundant `fill(0)` after `resize(n, 0)` in both locations
6. If the intent is to clear pre-existing data: use only `fill(0)` (if len == n) or `resize` + `fill` conditionally

## Affected Files

- `src/stealth.rs:786, 792` - Vec and RNG
- `src/fec.rs:363-366, 461-464` - double init

## Verification

- `cargo test` passes
- `cargo bench` (if FEC/stealth benchmarks exist) shows no regression
- Clippy clean
