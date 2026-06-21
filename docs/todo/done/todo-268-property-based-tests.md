# TODO-268: Add Property-Based Tests for Core Algorithms

## Severity: MEDIUM

## Context
The project has 6 fuzz targets (frame decoding, packet parsing, varint parsing, crypto operations, FEC encoding, connection handling) but no property-based tests using proptest or quickcheck. Property-based testing would complement fuzzing by testing algebraic properties (e.g., encode/decode round-trip, varint monotonicity, FEC recovery guarantee).

## Desired Outcome
- Add `proptest` as a dev-dependency.
- Create property-based tests for:
  - Varint encode/decode round-trip: `decode(encode(x)) == x` for all valid x
  - Frame encode/decode round-trip: `decode(encode(frame)) == frame`
  - FEC encode/decode: recovery succeeds when enough shards are present
  - AEAD seal/open round-trip: `open(seal(plaintext)) == plaintext`
  - ConnectionId comparison: reflexive, symmetric, transitive
- Target: at least 5 property tests covering the most critical paths.

## Files
- `Cargo.toml` (add proptest dev-dependency)
- New test files or additions to existing test modules

## Completion Criteria
- At least 5 property-based tests exist and pass.
- Tests cover round-trip correctness for varint, frame, FEC, and crypto paths.
- `cargo test` passes.
