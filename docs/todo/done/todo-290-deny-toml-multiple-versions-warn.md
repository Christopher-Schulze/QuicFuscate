# TODO-290: deny.toml multiple-versions = "warn" Should Be "deny"

## Problem
`deny.toml` uses `multiple-versions = "warn"` which only warns about duplicate crate versions instead of failing the build. For a security-critical project, duplicate versions increase supply-chain attack surface.

## Source
AI Model Review (GLM-5) - verified correct.

## Location
- `deny.toml`

## Fix
Change to `multiple-versions = "deny"` and add skip entries for any intentionally-duplicated crates.

## Acceptance Criteria
- `multiple-versions = "deny"` set
- `cargo deny check` passes (with appropriate skip entries if needed)
