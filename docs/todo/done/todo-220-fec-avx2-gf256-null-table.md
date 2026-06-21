# TODO-220: FEC AVX2 GF(256) Null Multiplication Table

## Severity: CRITICAL

## Problem

The AVX2 GF(256) multiplication function `gf_mul_avx2_single` in `src/fec.rs:680` has a lookup table (`tbl_lo`) that is completely filled with zeros:

```rust
let tbl_lo = _mm256_setr_epi8(
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
);
```

This means all GF(256) multiplications via AVX2 produce zero. When the `avx2` feature is enabled, all FEC repair packets will contain null data, causing total FEC recovery failure on AVX2-capable systems.

## Impact

- FEC repair packets become useless (all zeros)
- Packet loss cannot be recovered on AVX2 systems
- Silent data corruption: no error, just zero output
- The `avx2` feature flag is NOT default-enabled, mitigating immediate production impact
- Any future AVX2 enablement would silently break FEC

## Root Cause

The lookup table should contain the GF(256) multiplication products for the low nibble. The correct values depend on the generator polynomial (typically 0x1D for GF(2^8)). The table was likely a placeholder that was never populated.

## Fix

1. Compute correct GF(256) multiplication table for the low nibble using the irreducible polynomial
2. Populate `tbl_lo` with correct values
3. Add a corresponding `tbl_hi` table for the high nibble if not already correct
4. Add unit test: `gf_mul_avx2_single(a, b) == gf_mul_reference(a, b)` for all 256x256 input pairs
5. Add a compile-time or startup assertion that the table is non-zero

## Affected Files

- `src/fec.rs:680` - `gf_mul_avx2_single` function

## Verification

- Unit test: exhaustive parity check against reference scalar GF(256) multiplication
- Integration test: FEC encode/decode roundtrip with AVX2 feature enabled
- Ensure the `avx2` feature flag gates this path correctly

## Dependencies

None - standalone fix.
