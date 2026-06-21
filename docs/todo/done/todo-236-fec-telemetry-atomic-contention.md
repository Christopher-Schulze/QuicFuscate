# TODO-236: FEC Telemetry Atomic Contention in Hot Path

## Severity: MEDIUM

## Problem

`src/fec.rs` contains 19+ atomic counter increments (`.inc()` and `.fetch_add()`) per single FEC operation in hot paths. These span across multiple SIMD backend dispatchers:

**`.inc()` calls (samples):**
- Line 458: `FEC_SSSE3_OPS.inc()`
- Line 604: `FEC_GFNI_OPS.inc()`
- Line 706: `FEC_SIMD_ENCODE.inc()`
- Line 2725: `WIEDEMANN_USAGE.inc()`
- Line 5865: `FEC_SVE2_OPS.inc()`
- Line 6151: `FEC_AVX2_GF_OPS.inc()`
- Line 6240: `FEC_NEON_OPS.inc()`
- Line 6544: `FEC_GF16_VBMI2_OPS.inc()`

**`.fetch_add()` calls:**
- Lines 3504, 3507: RS_ENC_TIME_NS + counter
- Lines 3836, 3839: RS_DEC_TIME_NS + counter
- Line 4142: repairs_skipped counter
- Lines 4664-4673: FEC_SWITCH_REASON_* (4 separate fetch_add calls)
- Lines 6805-6949: FEC_MODE_SWITCHES + SIMD_USAGE_* (6+ fetch_add calls)

## Impact

- False sharing: adjacent atomic counters on the same cache line cause cross-core invalidation
- Memory ordering overhead: each atomic op is a barrier on x86 (LOCK prefix)
- On multi-threaded FEC paths this creates measurable contention
- 19 atomic ops per FEC encode/decode is excessive for observability

## Fix

1. Batch telemetry: accumulate counts in thread-local counters, flush to atomics periodically (e.g. every 64 or 256 ops)
2. Align hot atomic counters to separate cache lines (`#[repr(align(64))]`)
3. Use `Relaxed` ordering where sequential consistency is not required
4. Consider: reduce to 3-4 key counters per FEC path instead of 19+
5. Gate verbose counters behind a `telemetry-verbose` feature flag

## Affected Files

- `src/fec.rs` - multiple locations
- `src/optimize/telemetry.rs` - counter definitions

## Verification

- `cargo test` passes
- FEC encode/decode benchmarks show no regression (ideally improvement)
- Telemetry still reports accurate aggregate counts
