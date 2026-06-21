# TODO-224: env_flag_enabled and env_parse Utility Deduplication

## Severity: HIGH

## Problem

### env_flag_enabled - 4 implementations with different logic

1. `src/core.rs:173` - checks `!= "0"` and `!eq_ignore_ascii_case("false")`
2. `src/stealth.rs:238` - checks `== "1"` or `"true"` or `"on"`
3. `src/qftls.rs:563` - duplicate of core.rs logic
4. `src/qftls.rs:818` - checks `"1"` or `"true"` or `"yes"` or `"on"`

These have **different semantics**: core.rs treats everything except "0"/"false" as true, while stealth.rs treats everything except "1"/"true"/"on" as false. This means the same env var could be interpreted differently depending on which function reads it.

### env_parse - 3 implementations

1. `src/fec.rs:28` - standalone function
2. `src/brain.rs:123` - method on struct
3. `src/stealth.rs:3697` - `env_parse_first` variant

All parse env vars to numeric types but with slightly different error handling.

## Impact

- Same env var interpreted differently by different modules
- Bug-prone: setting `QUICFUSCATE_FOO=yes` works in qftls but not in stealth
- Maintenance burden: changes to env parsing logic must be replicated 4x/3x
- Violates DRY principle

## Fix

1. Create a single `src/env_utils.rs` module (or add to existing utility location)
2. Define one canonical `env_flag(name: &str) -> bool` with clear semantics:
   - Recommended: `"1"`, `"true"`, `"yes"`, `"on"` (case-insensitive) = true, everything else = false
3. Define one canonical `env_parse<T: FromStr>(name: &str, default: T) -> T`
4. Replace all 4 env_flag implementations and all 3 env_parse implementations
5. Add unit tests for the canonical functions

## Affected Files

- `src/core.rs:173`
- `src/stealth.rs:238, 3697`
- `src/qftls.rs:563, 818`
- `src/fec.rs:28`
- `src/brain.rs:123`
- New: utility module for env helpers

## Verification

- `cargo test` passes
- `cargo clippy` passes
- Grep confirms zero remaining local env_flag/env_parse definitions
