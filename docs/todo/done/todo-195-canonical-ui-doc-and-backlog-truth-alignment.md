# TODO-195: Canonical UI Documentation and Backlog Truth Alignment

## Status
**COMPLETED**

## Severity
**HIGH**

## Context
The current docs tell multiple conflicting frontend stories:

- some documents describe React as the active reference path
- others describe the Svelte rebuild as active
- the backlog claims frontend progress that is not yet fully integrated into CI/release truth
- at least one expected architecture document is missing entirely
- several statements about product-facing controls and UI behavior are no longer true

This is not a cosmetic issue. It prevents reviewers and operators from understanding what is actually shipped.

## Root Cause
Documentation tracked local development intent rather than repository-integrated truth. Multiple documents were updated independently without a final convergence pass after the Svelte rebuild.

## Fix Plan
1. Define the canonical frontend story: Svelte only, React retired.
2. Update `README.md`, `docs/DOCUMENTATION.md`, and `docs/MAP.md` to that single story.
3. Fix backlog truth so active, partial, completed, and superseded items match reality.
4. Recreate or replace missing architecture-facing documentation where required.
5. Remove stale product claims such as React references or product-facing XOR controls.

## Acceptance Criteria
- Frontend documentation names only the active Svelte product path.
- Backlog entries reflect real status, not wishful status.
- Product-facing control descriptions match the actual UI.
- Reviewer-facing architecture pointers are complete and internally consistent.

## Dependencies
- TODO-191 and TODO-192 for final code and pipeline truth
- TODO-196 for XOR control demotion wording
- TODO-198 for final control-ownership wording

## Affected Files
- `README.md`
- `docs/DOCUMENTATION.md`
- `docs/MAP.md`
- `docs/todo.md`
- `docs/context.md`
- `docs/todo/todo-190-full-ui-revamp.md`
- `docs/todo/todo-128-password-minimum-increase.md`
