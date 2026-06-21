# TODO-265: Fix .gitattributes Stale Path References

## Severity: LOW

## Context
`.gitattributes` references 3 paths that do not exist on disk:
1. `releases/**`
2. `ui/**`
3. `scripts/artifacts/logs/**`

These are remnants from earlier project structure and serve no purpose. They do not cause errors but are misleading.

## Desired Outcome
- Remove references to non-existent paths from `.gitattributes`.
- Verify remaining entries still match actual project structure.
- Add entries for current paths if needed (e.g., `assets/web-admin/**` for binary handling).

## Files
- `.gitattributes`

## Completion Criteria
- All paths in `.gitattributes` correspond to real directories.
- No stale references.
