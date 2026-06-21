# TODO-204: Toolchain Baseline Upgrade to Current Stable Rust

## Status
**COMPLETED - 2026-03-17**

## Severity
**HIGH**

## Context
The current main workspace declares `rust-version = "1.80"`, yet the code already wants newer standard-library helpers and modern Clippy expectations. The repository should either stay rigorously within 1.80 or move intentionally to the current stable Rust baseline. The requested direction is to move forward.

## Objective
Adopt the current stable Rust toolchain across the main workspace and supporting validation stack.

## Scope
- Update Rust toolchain metadata.
- Align CI and developer expectations to the new stable baseline.
- Validate the main workspace and the Tauri side against the upgraded toolchain.
- Document the new baseline cleanly.

## Detailed Work Plan
1. Choose the current stable Rust release as the new canonical baseline.
2. Update `Cargo.toml` and any explicit toolchain files.
3. Re-run build/test/clippy on the new baseline.
4. Resolve newly exposed incompatibilities or lints.
5. Update docs and validation guidance to the new baseline.

## Tracking Checklist
- [x] New stable toolchain baseline selected.
- [x] Main workspace metadata updated.
- [x] Supporting toolchain files updated.
- [x] CI expectations updated.
- [x] Docs updated to the new baseline.

## Completion Notes
- Upgraded the canonical workspace baseline to Rust `1.93.0`.
- Updated root toolchain metadata, CI setup, and deployment/documentation guidance.
- Revalidated the main Rust workspace and the Tauri host on the upgraded stable baseline.

## Acceptance Criteria
- The workspace declares and uses the intended current stable Rust baseline.
- Build, test, and Clippy gates run successfully on that baseline.
- Docs and CI no longer imply the old baseline.

## Dependencies
- TODO-205
- TODO-206

## Affected Files
- `Cargo.toml`
- `rust-toolchain.toml`
- `.github/workflows/ci.yml`
- `docs/DOCUMENTATION.md`
- `README.md`
