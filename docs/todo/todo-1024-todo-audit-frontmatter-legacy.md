---
id: TODO-1024
title: audit-todo-consistency.sh permanently red - 95 legacy files lack YAML frontmatter
severity: LOW
phase: L
priority: P3
status: DONE
created: 2026-09-21
depends_on: []
---

# TODO-1024: Resolve the 95 frontmatter violations or grandfather the legacy format

## Context

`docs/todo/audit-todo-consistency.sh` currently FAILs with 95
violations, all of the same class: legacy detail files (roughly
TODO-978..996 and earlier generations) carry no YAML frontmatter block
(`--- id/status/... ---`). Newer files (TODO-1000+) use frontmatter
consistently.

Because the gate is permanently red, its signal is degraded: a real
new violation (missing index entry, broken cross-reference, DONE file
without classified acceptance) would be invisible inside the noise.

## Objective

Pick one, implement, and make the gate green again:

- **Option A (backfill)**: add minimal frontmatter
  (`id`, `title`, `status`, `created`) to the 95 legacy files.
  Mechanical, one scripted pass; keeps one uniform format.
- **Option B (grandfather)**: teach the audit that files below a
  declared cutover id (or files in a `legacy` allowlist) are exempt
  from the frontmatter check while keeping all other checks active.
  Less churn, but two formats remain forever.

Option A is preferred — the frontmatter is small, the pass is
scriptable, and a uniform format keeps the audit simple.

## Acceptance

- `audit-todo-consistency.sh` exits 0 on a clean tree.
- No information lost: legacy files keep their full prose bodies;
  only the header block is added.
- The audit's remaining checks (index cross-references, DONE
  acceptance classification) still run over all files.

## Implementation (2026-09-21)

Option A. 65 legacy details received minimal frontmatter
(`id`/`title`/`status`/`created`); bodies unchanged. The audit now
accepts the live vocabulary (PARTIAL, BLOCKED, IN_PROGRESS, ACTIVE,
COMPLETED, CLOSED, AUDIT_COMPLETE, QUEUED), tokenizes annotated
`status:` values, and Check 3 reads `### TODO-N` heading bullets in
`docs/todo.md` (legacy `**STATUS**` tables still work). Four real
index/detail drifts were aligned (902/1009/1010/1011 -> PARTIAL).

`docs/todo/audit-todo-consistency.sh` exits 0 (353 files, 0
violations). Check 3/4 are live signal again.
