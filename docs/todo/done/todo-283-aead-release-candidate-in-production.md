# TODO-283: Replace aead 0.6.0-rc.10 Release Candidate with Stable

## Problem
`aead = "0.6.0-rc.10"` is a release candidate used as a production dependency. RC versions can have breaking changes before final release and are not guaranteed to be stable.

## Source
AI Model Review (Gemini 3.1 Pro, GLM-5) - verified correct.

## Location
- `Cargo.toml:30` - `aead = { version = "0.6.0-rc.10", features = ["alloc"], optional = true }`

## Fix
Check if aead 0.6.x stable exists. If not, document the RC usage with justification. If stable exists, upgrade.

## Acceptance Criteria
- aead dependency is either stable or has documented justification for RC usage
- `cargo build` passes
- All tests pass
