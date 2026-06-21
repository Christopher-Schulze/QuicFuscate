# Tooling Audit and Naming Standardization

## Scope
- All scripts under `scripts/` (tests, benchmarks, utilities, audits).
- Naming consistency, redundancy, structure, and output schema.

## Findings (Initial Scan)
- Naming prefixes are consistent across scripts; only `scripts/tests/lib/lib-common.sh` is intentionally exempt.
- No duplicate prefixes detected after earlier consolidation.

## Tasks
1) Validate directory taxonomy (tests/benchmarks/utils/audits/lib) matches naming.
2) Confirm all suites use shared JSON schema and lib-common helpers.
3) Check for redundant wrappers and alias scripts; remove or document.
4) Ensure every suite has a micro/fast/smoke counterpart only where needed.
5) Verify all scripts are deterministic with clear output artifacts.

## Completion Criteria
- Naming is consistent and documented.
- Redundant scripts removed or explicitly justified.
- All suites produce standard JSON artifacts.
