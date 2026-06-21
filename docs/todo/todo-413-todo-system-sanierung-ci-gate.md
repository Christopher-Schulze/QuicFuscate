---
id: TODO-413
title: TODO-System-Sanierung + CI-Gate for Status-Feld-Pflicht
severity: HIGH
phase: "0"
priority: P0
status: DONE
created: 2026-07-23
resolved: 2026-07-23
depends_on: []
supersedes: []
---

# TODO-413: TODO-System-Sanierung + CI-Gate

## Problem

The TODO system has drifted catastrophically:
- **33 files** (TODO-356..388) have **no YAML frontmatter** and **no `status:` field** — old format (`## Severity:` headers) never backfilled.
- **11 files** (TODO-390,391,392,395,396,397,398,399,400,401,409) were marked `**DONE**` in `todo.md` master index but are actually **OPEN** per code inspection (2026-07-23).
- No CI gate enforces the presence of a `status:` field, so drift recurs silently.
- `docs/todo.md` and `docs/TODO.md` are the same file (case-insensitive FS) — no duplicate, but referenced inconsistently in docs.

This makes the entire TODO backlog untrustworthy as a planning instrument.

## Acceptance

1. **All 63 TODO detail files** (356-418) have YAML frontmatter with `status:` field set to one of: `OPEN`, `DONE`, `DEFERRED`, `SCRAP`.
2. **`todo.md` master index** matches the status in every detail file — zero discrepancies.
3. **CI gate** in `scripts/tests/audits/audit-runtime-guardrails.sh` (or new `audit-todo-consistency.sh`) fails when:
   - A `docs/todo/todo-*.md` file lacks a `status:` field in YAML frontmatter.
   - A `status:` value is not in `{OPEN, DONE, DEFERRED, SCRAP}`.
   - The master `todo.md` table status for an ID disagrees with the detail file status.
4. **356-388 backfill**: Each of the 33 files gets YAML frontmatter prepended (non-destructive — original content preserved below frontmatter). Status set to `DONE` for all 33 (verified: these were completed in Sessions 36-41, code confirms).
5. **SCRAP/DEFERRED markers** set in individual files per the radical replan:
   - SCRAP: 369, 370, 371, 373, 374, 377, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388
   - DEFERRED: 356, 357, 358, 362, 372, 378
6. **Superseded notes** added to 396, 397, 398 (→417), 409 (→414), 412 (→418) in their detail files.

## Fix Plan

### Step 1: Backfill YAML frontmatter for 356-388 (33 files)
For each file:
- Read current content.
- Prepend YAML frontmatter block:
  ```yaml
  ---
  id: TODO-{id}
  title: {extracted from H1 or filename}
  severity: {extracted from `## Severity:` line}
  phase: legacy
  priority: legacy
  status: DONE  # or DEFERRED/SCRAP per replan
  created: 2026-03-27
  backfilled: 2026-07-23
  ---
  ```
- Preserve all original content below frontmatter.
- Remove the now-redundant `## Severity:` line (info is in frontmatter).

### Step 2: Correct status in 389-411 detail files
- 390, 391, 392, 395, 399, 400, 401: Change `status: DONE` → `status: OPEN` in YAML.
- 396, 397, 398: Change `status: DONE` → `status: OPEN`, add `superseded_by: TODO-417`.
- 409: Change `status: DONE` → `status: OPEN`, add `superseded_by: TODO-414`.
- 412: Add `superseded_by: TODO-418`.

### Step 3: Set SCRAP/DEFERRED in individual files
- For SCRAP files: `status: SCRAP`, add `scrap_reason:` field.
- For DEFERRED files: `status: DEFERRED`, add `defer_reason:` field.

### Step 4: CI-Gate script
Create `scripts/tests/audits/audit-todo-consistency.sh`:
- Scan `docs/todo/todo-*.md` for YAML frontmatter.
- Validate `status:` field presence and value.
- Cross-check against `todo.md` master index table rows.
- Exit non-zero on any violation.
- Wire into `scripts/tests/test-audit-all.sh` or CI workflow.

### Step 5: Final consistency check
- Run the new audit script.
- Manually verify `todo.md` master index matches all detail files.

## Files

- `docs/todo/todo-356-*.md` through `docs/todo/todo-388-*.md` (33 files, frontmatter backfill)
- `docs/todo/todo-390-*.md` through `docs/todo/todo-412-*.md` (status corrections)
- `docs/todo.md` (already corrected 2026-07-23)
- `scripts/tests/audits/audit-todo-consistency.sh` (new)
- `scripts/tests/test-audit-all.sh` or `.github/workflows/ci.yml` (wire new audit)

## Notes

- No UI changes. No stealth/FEC/performance code changes.
- This is purely a documentation/governance task.
- Precondition for all subsequent TODOs (414-418) — without a trustworthy backlog, planning is impossible.
- The 33-file backfill is mechanical but voluminous — consider a script to generate frontmatter from existing `## Severity:` lines.
