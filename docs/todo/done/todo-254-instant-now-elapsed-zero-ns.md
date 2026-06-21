# TODO-254: Fix Instant::now().elapsed() Always-Zero Anti-Fingerprinting Seed

## Severity: LOW

## Context
`src/transport/recovery.rs:12-13` creates an `Instant` and immediately calls `.elapsed()`, which always returns ~0 nanoseconds. This is used as an "anti-fingerprinting mix" for the BBR3 RNG seed, but it contributes zero entropy. The actual entropy comes from `fill_secure()`, making this line dead code that gives a false sense of additional randomization.

## Desired Outcome
- Remove the `Instant::now().elapsed()` call if it adds no entropy, OR
- If timing jitter is desired, use a proper approach (e.g., measure actual operation duration or use `std::hint::black_box` to prevent optimization).
- Document the RNG seeding strategy clearly.

## Files
- `src/transport/recovery.rs` (lines ~10-15)

## Completion Criteria
- No misleading "anti-fingerprinting" code that does nothing.
- RNG seeding is clearly documented.
- `cargo test` passes, clippy clean.
