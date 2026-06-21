# TODO-134: Float-to-u64 Cast Loses Precision in Delivery Rate Calculation

## Status
**COMPLETED**

## Completion Note
Fixed by keeping delivery_rate as f64 through intermediate calculations. Introduced `delivery_rate_f64` variable that stays as f64, only casting to u64 at the final assignment to `delivery_rate`. This preserves precision for low-bandwidth scenarios and short measurement intervals.

## Severity
**MEDIUM**

## Context
In `src/transport/recovery.rs:298-307`, the delivery rate calculation casts from `f64` to `u64` prematurely:

```rust
delivery_rate = (delivered as f64 / elapsed) as u64
```

This truncates the fractional part of the delivery rate before it is used in further calculations (e.g., pacing rate computation, bandwidth estimation). For low-bandwidth scenarios or short measurement intervals, this truncation can lose significant precision - e.g., a true rate of 1.7 MB/s becomes 1 MB/s (41% error).

## Root Cause
Early cast from `f64` to `u64` in the calculation pipeline. The delivery rate is an intermediate value used in pacing_rate and bandwidth estimation, where fractional precision matters.

## Fix Plan
1. Keep `delivery_rate` as `f64` throughout the calculation pipeline
2. Change the field type in the relevant struct from `u64` to `f64` (or introduce a dedicated `DeliveryRate` newtype wrapping `f64`)
3. Only cast to `u64` at the final `pacing_rate` assignment where an integer bytes-per-second value is needed
4. Update all downstream consumers of `delivery_rate` to work with `f64`
5. Verify bandwidth estimation and probe decisions use the higher-precision value
6. Add a unit test that demonstrates precision loss with the old approach vs the fix

## Acceptance Criteria
- No precision loss in intermediate delivery rate calculations
- `delivery_rate` remains `f64` until final pacing_rate integer assignment
- Unit test proves precision is preserved for edge cases (low bandwidth, short intervals)
- All downstream consumers updated and tested

## Dependencies
- May affect `src/transport/recovery.rs` struct definitions
- Downstream consumers of delivery_rate in congestion control logic

## Affected Files
- `src/transport/recovery.rs`
