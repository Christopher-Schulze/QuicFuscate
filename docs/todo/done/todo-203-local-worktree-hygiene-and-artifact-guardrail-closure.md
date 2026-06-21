# TODO-203: Local Worktree Hygiene and Artifact Guardrail Closure

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The local repository periodically accumulates generated caches, transient build trees, Playwright artifacts, and Finder debris. Those artifacts create noise, increase storage pressure, and can accidentally obscure the real source-of-truth state.

## Objective
Establish a clean local artifact posture and guardrail against recurring worktree pollution.

## Scope
- Remove residual transient artifacts from the local worktree.
- Verify `.gitignore` covers the current generated directories.
- Prevent `.DS_Store` and similar local debris from reappearing unnoticed.
- Keep real publish artifacts and real source files distinct from caches.

## Detailed Work Plan
1. Inventory recurring local artifact categories.
2. Remove any residual transient debris that is safe to delete.
3. Tighten ignore rules where active generated directories are still leaking.
4. Re-run artifact sweeps after staging and validation.
5. Document the expected local-clean state.

## Tracking Checklist
- [x] Generated cache directories inventoried.
- [x] Residual build/test debris removed.
- [x] `.gitignore` reviewed against current toolchain output.
- [x] Repo-wide `.DS_Store` sweep clean.
- [x] Post-validation artifact sweep repeated.

## Acceptance Criteria
- No local transient artifact remains as accidental source-of-truth content.
- `.gitignore` covers current generated output paths.
- Repo-wide artifact sweeps come back clean.

## Dependencies
- TODO-200
- TODO-202
- TODO-217

## Affected Files
- `.gitignore`
- transient build/test output trees
- `docs/context.md`
