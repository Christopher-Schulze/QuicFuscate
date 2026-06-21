# TODO-262: Upgrade rand Crate and Consolidate RNG Usage

## Severity: MEDIUM

## Context
Two issues:
1. `Cargo.toml:31` uses `rand = "0.8"`, which is outdated (current: 0.9.x). The 0.8 line is in maintenance mode.
2. `src/qftls.rs:147,199,243,275` uses `rand::random()` (ThreadRng) for TLS timing jitter instead of the project's canonical `fill_secure()` from `src/rng.rs`. This inconsistency means some randomness paths use the project's audited RNG and others use the default ThreadRng.

## Desired Outcome
- Upgrade `rand` from 0.8.x to 0.9.x (may require API changes for `Rng` trait imports).
- Audit all `rand::random()` and `rand::thread_rng()` call sites.
- For security-sensitive randomness: use `fill_secure()` from rng.rs.
- For non-security randomness (jitter, shuffling): `fastrand` or `rand::random()` is acceptable, but document the choice.

## Files
- `Cargo.toml` (rand dependency)
- `src/rng.rs` (canonical RNG module)
- `src/qftls.rs` (lines ~147, 199, 243, 275)
- Other files using `rand::*` directly

## Completion Criteria
- `rand` upgraded to 0.9.x.
- Security-sensitive RNG paths use `fill_secure()`.
- Non-security paths are documented.
- `cargo test` passes, clippy clean.
