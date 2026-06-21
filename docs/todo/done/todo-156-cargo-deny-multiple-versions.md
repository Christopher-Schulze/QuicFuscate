# TODO-156: Enforce cargo-deny Multiple Versions and Raise License Confidence

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The project's `deny.toml` configuration has `multiple-versions = "allow"`, which permits duplicate crate versions in the dependency tree. This leads to larger binaries, increased compile times, and potential version conflicts where two versions of the same crate coexist with incompatible behavior.

Additionally, the `license.confidence-threshold` is set to `0.8` (80%), which is too permissive - it may allow dependencies with ambiguous or incorrectly detected licenses to pass the check.

- `deny.toml`: `multiple-versions = "allow"` in `[bans]` section
- `deny.toml`: `confidence-threshold = 0.8` in `[licenses]` section

## Root Cause
During initial setup, `multiple-versions` was set to `"allow"` to avoid dealing with dependency resolution conflicts. The license threshold was set conservatively low to avoid false positives. Neither was revisited as the dependency tree matured.

## Fix Plan
1. Change `multiple-versions = "allow"` to `multiple-versions = "deny"` in `deny.toml`
2. Run `cargo deny check bans` to identify all duplicate crate versions
3. For each duplicate:
   - Check if a version unification is possible (update one dependency to use a compatible version)
   - Use `cargo update -p <crate>` to try resolving naturally
   - If unresolvable, add explicit `skip` entries in `deny.toml` with justification:
     ```toml
     [[bans.skip]]
     name = "some-crate"
     version = "=1.0.0"
     # Reason: required by dependency X which hasn't updated yet
     ```
4. Increase `confidence-threshold` from `0.8` to `0.95` in `[licenses]` section
5. Run `cargo deny check licenses` to verify no new license issues
6. Run `cargo deny check` (full check) to validate all sections pass
7. Document any skipped duplicates and their resolution timeline

## Acceptance Criteria
- `multiple-versions = "deny"` in deny.toml
- `cargo deny check bans` passes (no unacknowledged duplicate versions)
- Any `skip` entries have documented justification
- `confidence-threshold = 0.95` in deny.toml
- `cargo deny check licenses` passes at the higher threshold
- `cargo deny check` passes fully in CI
- Binary size reduction documented (from removing duplicate crates)

## Dependencies
- `cargo-deny` tool (likely already available if deny.toml exists)
- Upstream dependency updates may be needed to resolve duplicates

## Affected Files
- `deny.toml` (change multiple-versions, increase confidence-threshold, add skip entries)
- `Cargo.toml` (may need version adjustments to resolve duplicates)
- `Cargo.lock` (will update with dependency resolution changes)
