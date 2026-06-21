# TODO-215: Script, Smoke, Audit, and CI Svelte-Truth Harmonization

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The repository now has a Svelte-first workflow, an upgraded toolchain plan, and a corrected publish path. All active scripts, smoke runners, audits, and CI entrypoints must align to that exact local truth.

## Objective
Make all active script and CI entrypoints agree on the same Svelte-first, current-toolchain, current-publish workflow.

## Scope
- CI workflow files.
- Build and local-run scripts.
- Smoke and audit scripts.
- Script help text, comments, and assumptions.

## Detailed Work Plan
1. Audit every active script and CI job that touches frontend or publish paths.
2. Remove stale React-era assumptions from active paths.
3. Align toolchain and quality-gate expectations to the chosen Rust baseline.
4. Align smoke/audit scripts to the current frontend/package setup.
5. Re-run the active script entrypoints after harmonization.

## Tracking Checklist
- [x] Active script inventory completed.
- [x] CI updated.
- [x] Build/local-run scripts updated.
- [x] Smoke/audit scripts updated.
- [x] Active script entrypoints revalidated.

## Acceptance Criteria
- No active script or CI path points to stale frontend truth.
- Toolchain and quality assumptions are consistent across script surfaces.
- Smoke and audit entrypoints exercise the real active workflow.

## Dependencies
- TODO-201
- TODO-202
- TODO-204
- TODO-205

## Affected Files
- `.github/workflows/ci.yml`
- `scripts/build/**`
- `scripts/tests/smoke/**`
- `scripts/tests/audits/**`
- `scripts/utils/**`
