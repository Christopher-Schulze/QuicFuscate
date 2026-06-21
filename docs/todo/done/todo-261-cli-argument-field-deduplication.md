# TODO-261: Deduplicate CLI Argument Fields Between Client and Server

## Severity: LOW

## Context
`src/main.rs` defines client and server subcommands with ~12 duplicated argument fields: profile, os, fec_mode, pool_capacity, etc. These appear as separate fields in both subcommand structs. Using clap's `#[command(flatten)]` with a shared struct would eliminate the duplication.

## Desired Outcome
- Extract common CLI arguments into a `SharedArgs` struct.
- Use `#[command(flatten)]` in both client and server subcommands.
- Maintain identical CLI behavior and help output.

## Files
- `src/main.rs` (Commands enum and subcommand structs)

## Completion Criteria
- No duplicated CLI argument definitions.
- CLI behavior is identical (same flags, same defaults, same help text).
- `cargo test` passes, clippy clean.
