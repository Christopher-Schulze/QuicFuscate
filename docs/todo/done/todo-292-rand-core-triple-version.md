# TODO-292: password-hash/rand/rand_core Triple Version Fragility

## Problem
`password-hash 0.5` depends on `rand_core 0.6`, while the project uses `rand 0.9` (which depends on `rand_core 0.9`). This creates multiple `rand_core` versions in the dependency tree - a maintenance and potential compatibility issue.

## Source
AI Model Review (Gemini 3.1 Pro) - verified correct. Compatibility shim exists in `admin_http.rs:30-31`.

## Location
- `Cargo.toml` - `password-hash = "0.5"`, `rand_core = "0.6"`, `rand = "0.9"`
- `src/implementations/server/admin_http.rs:30-31` - compatibility adapter

## Fix
Check if `password-hash 0.6` exists with `rand_core 0.9` support. If not, document the workaround. Consider if argon2 crate has a newer version that resolves this.

## Acceptance Criteria
- Either upgraded to compatible versions OR documented with clear justification
- No silent version conflicts
