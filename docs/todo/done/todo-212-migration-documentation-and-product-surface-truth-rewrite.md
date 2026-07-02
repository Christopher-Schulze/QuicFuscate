# TODO-212: Migration Documentation and Product-Surface Truth Rewrite

## Status
**COMPLETED - 2026-03-17**

## Severity
**HIGH**

## Context
Migration-related docs, examples, and tracking notes must end in a professional, exact state: neither overpromising nor underselling, and fully aligned with the real implementation and tests.

## Objective
Rewrite the migration-related documentation surface so it is technically exact, product-appropriate, and consistent across all canonical docs.

## Scope
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `README.md`
- relevant TODO/detail files
- `docs/todo.md`, `docs/DOCUMENTATION.md`, and `docs/MAP.md`

## Detailed Work Plan
1. Gather the final migration contract after implementation and test completion.
2. Rewrite migration sections in the canonical docs.
3. Update examples, suite descriptions, and metrics wording.
4. Mark outdated historical notes as superseded where needed.
5. Perform a final docs-only anti-drift sweep.

## Tracking Checklist
- [x] Final migration contract collected.
- [x] Canonical docs updated.
- [x] Examples and metrics wording updated.
- [x] Historical mismatches marked or removed.
- [x] Docs anti-drift sweep completed.

## Completion Notes
- Rewrote the canonical migration section in `docs/DOCUMENTATION.md` to describe validation start vs validated path activation precisely.
- Updated suite inventory wording and active config comments to match the validated migration contract.
- `README.md` and `docs/MAP.md` required no direct migration wording changes because they did not contain an active migration feature claim.

## Acceptance Criteria
- Canonical docs describe migration truth exactly.
- No remaining canonical doc overclaims migration validation or success semantics.
- Tracking docs remain useful without becoming contradictory.

## Dependencies
- TODO-209
- TODO-210
- TODO-211
- TODO-219

## Affected Files
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `README.md`
- `docs/todo.md`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
