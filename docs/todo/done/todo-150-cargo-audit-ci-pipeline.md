# TODO-150: Add cargo audit Step to CI Pipeline

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The CI pipeline in `.github/workflows/ci.yml` does not include a `cargo audit` step. Security advisories published in the RustSec Advisory Database for any of the project's dependencies will go undetected until manually checked. For a security-focused project like QuicFuscate, this is a significant gap.

- `.github/workflows/ci.yml`: No `cargo audit` or `cargo deny audit` step present

## Root Cause
The CI pipeline was set up with build, test, and lint steps but omitted dependency security scanning. `cargo audit` was likely run manually (if at all) but never automated.

## Fix Plan
1. Add `cargo install cargo-audit` step to CI (or use `actions-rs/audit-check@v1`)
2. Add a new job or step in the existing CI workflow:
   ```yaml
   - name: Security audit
     run: |
       cargo install cargo-audit --locked
       cargo audit --deny warnings
   ```
3. Alternative: use `cargo deny check advisories` since `deny.toml` already exists - this leverages the existing deny configuration
4. Ensure the step runs on every PR and push to main
5. Configure to fail the pipeline on any known vulnerability (`--deny warnings`)
6. Consider adding `--ignore RUSTSEC-XXXX-XXXX` mechanism for acknowledged/mitigated advisories with documented justification

## Acceptance Criteria
- CI pipeline includes a `cargo audit` or equivalent security check step
- Pipeline fails when a dependency has a known vulnerability
- The step runs on every PR and every push to main
- Any ignored advisories are documented with justification

## Dependencies
- `cargo-audit` tool or `cargo-deny` (deny.toml already exists in project)
- RustSec Advisory Database (fetched at CI runtime)

## Affected Files
- `.github/workflows/ci.yml` (add audit job/step)
- `deny.toml` (may need advisories section configuration)
