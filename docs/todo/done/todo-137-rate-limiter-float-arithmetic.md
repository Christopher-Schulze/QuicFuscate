# TODO-137: Rate Limiter Uses Float Arithmetic for Token Refill

## Status
**COMPLETED**

## Completion Note
Replaced float-based token refill calculation with integer-only math using microsecond precision: `(elapsed.as_micros() * refill_rate as u128) / refill_interval.as_micros()`. Includes safe saturation to u64 range for overflow protection. Eliminates platform-dependent float rounding and accumulated drift.

## Severity
**MEDIUM**

## Context
In `src/implementations/server/limits.rs:113`, the token bucket rate limiter uses `f64` for token refill calculation:

```rust
elapsed.as_secs_f64() / refill_interval.as_secs_f64() * refill_rate
```

Problems with float arithmetic here:
- Non-deterministic across platforms (x87 vs SSE, different rounding modes)
- Accumulated floating-point error over many refill cycles can drift token count
- Edge case: very small elapsed times can produce subnormal floats
- Token count can become slightly negative or exceed bucket capacity due to rounding

For a security-relevant component (rate limiting), deterministic behavior is essential. An attacker could potentially exploit float precision issues to get slightly more tokens than intended.

## Root Cause
Convenience of `as_secs_f64()` used instead of integer-safe arithmetic. The refill calculation can be done entirely with integer math.

## Fix Plan
1. Replace float calculation with integer-only math:
   ```rust
   // tokens_to_add = elapsed_nanos * refill_rate / interval_nanos
   let elapsed_nanos = elapsed.as_nanos() as u64;
   let interval_nanos = refill_interval.as_nanos() as u64;
   let tokens_to_add = elapsed_nanos.saturating_mul(refill_rate) / interval_nanos;
   ```
2. Handle remainder tracking to avoid losing fractional tokens:
   - Store `remainder_nanos` between refill calls
   - Add remainder to next elapsed calculation
3. Use `saturating_add` for token accumulation to prevent overflow
4. Clamp token count to bucket capacity with `min()`
5. Add unit tests for:
   - Exact token count after known elapsed time
   - No drift after many small refill cycles
   - Deterministic behavior across repeated runs

## Acceptance Criteria
- No float arithmetic in rate limiter token calculation
- Deterministic, platform-independent behavior
- No token drift over extended operation
- Remainder tracking prevents lost fractional tokens
- Unit tests prove determinism and correctness

## Dependencies
- None

## Affected Files
- `src/implementations/server/limits.rs`
