# TODO-250: Remove Unimplemented Congestion Control Variants

## Severity: LOW

## Context
`src/transport.rs:144` defines `CongestionControlAlgorithm` with 6 variants: Reno, Cubic, BBR, Ledbat, BBR2, BBR3. Only BBR3 is actually implemented in `src/transport/recovery.rs`. The config accepts all 6 variants but silently ignores 5 of them, falling back to BBR3.

## Desired Outcome
- Remove unimplemented variants (Reno, Cubic, BBR, Ledbat, BBR2) from the enum, OR
- Add a config validation warning when a non-BBR3 algorithm is selected, OR
- Feature-gate the unimplemented variants behind a future `multi-cc` flag.

## Files
- `src/transport.rs` (~line 144)
- `src/transport/recovery.rs`
- `config/quicfuscate.toml` (cc_algorithm field)

## Completion Criteria
- Config validation warns or errors on selection of unimplemented CC algorithms.
- No silent behavioral mismatch between config and runtime.
- `cargo test` passes, clippy clean.
