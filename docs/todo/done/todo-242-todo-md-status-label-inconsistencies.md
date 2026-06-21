# TODO-242: todo.md Status Label Inconsistencies

## Severity: LOW

## Problem

7 TODOs in `docs/todo.md` are labeled `(active)` in their heading but their detail files show `**COMPLETED**`:

| TODO | todo.md Label | Detail File Status |
|------|--------------|-------------------|
| 192 | (active) | COMPLETED |
| 197 | (active) | COMPLETED |
| 215 | (active) | COMPLETED |
| 216 | (active) | COMPLETED |
| 217 | (active) | COMPLETED |
| 218 | (active) | COMPLETED |
| 219 | (active) | COMPLETED |

## Fix

1. Update all 7 headings in `docs/todo.md` from `(active)` to `(completed)`:
   - Line 478: `### 192. ... (active)` -> `(completed)`
   - Line 503: `### 197. ... (active)` -> `(completed)`
   - Line 593: `### 215. ... (active)` -> `(completed)`
   - Line 598: `### 216. ... (active)` -> `(completed)`
   - Line 603: `### 217. ... (active)` -> `(completed)`
   - Line 608: `### 218. ... (active)` -> `(completed)`
   - Line 613: `### 219. ... (active)` -> `(completed)`

## Affected Files

- `docs/todo.md` - 7 status label corrections

## Verification

- Grep for `(active)` in todo.md returns no results for completed items
- Detail files and index are consistent
