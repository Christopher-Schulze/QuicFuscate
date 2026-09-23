---
id: TODO-1119
title: Archive completed task details and repair their links
severity: LOW
phase: S
priority: P2
status: DONE
created: 2026-09-23
depends_on: []
---

# TODO-1119: Archive completed task details

## Why and evidence

`docs/todo/` still contains 327 detail files whose frontmatter status is
`DONE` or `COMPLETED`, including TODO-1110. The existing `docs/todo/done/`
directory is the archive. `docs/todo.md` pointed to the active paths for 326
of these files; TODO-892 already points to its missing archive destination.
Of the 327 files, 133 are Git tracked and 194 are local, ignored task files.

## Target contract

- Every detail with an unambiguous completed status resides at its identical
  basename under `docs/todo/done/`; its former active path is absent. Verify
  byte identity immediately after each move, then allow only exact reference
  repairs inside moved files. Preserve Git tracking status and ignore policy.
- Every exact reference to a moved path in the owning documentation resolves
  to the archive path. Do not alter historical task disposition or claim that
  a completed task's implementation has been re-audited.
- Keep open, active and ambiguous task details in their existing locations.
  Report any reverse inconsistency found in the archive separately.

## Implementation and proof

- [x] Inventory completed active details, tracking status, references,
      destination conflicts and content hashes before moving.
- [x] Move tracked sources with `git mv` and local ignored sources with `mv`;
      verify exact byte identity and absence of every old path.
- [x] Surgically update the task board and other exact path references, then
      check that every board detail link resolves.

## Acceptance

- Zero `DONE` or `COMPLETED` detail files remain directly under `docs/todo/`.
- All 327 archived files matched their original SHA-256 immediately after the
  moves, and no destination was overwritten. Eight moved files then received
  only exact path-reference repairs. All 987 board detail links and 1,094
  task-path references resolve; no completed detail remains in the active
  directory. Already archived TODO-720, TODO-721, TODO-722 and TODO-723 had
  `OPEN` metadata despite completed board records; their statuses and
  completed steps are reconciled without a new implementation audit.

## Follow-up: 2026-09-23

- Archived 19 further closed details: TODO-980 through TODO-994, TODO-1028,
  TODO-1042, TODO-1043 and TODO-1045. TODO-980 through TODO-994 had stale
  `OPEN` frontmatter despite completed implementation/proof in their details
  and board; their status now reads `DONE`. The refused and skipped decisions
  keep their original `REFUSED`/`SKIP` dispositions. This move does not
  re-audit their implementation or close any stated follow-up.
- Each source existed and each archive destination was absent before its
  move. Tracked sources used `git mv`; the ignored local TODO-988 used `mv`.
  The 19 board links now point to the archive. Local validation found 993/993
  board links resolving and zero `DONE`/`COMPLETED`/`CLOSED` frontmatter files
  directly under `docs/todo/`.
- TODO-884 was inspected but not archived. Its recorded bakeoff decision
  does not satisfy its original promotion criteria, whose decision rule
  explicitly requires a blocked disposition when neither family qualifies.
  Its board and detail now both read `BLOCKED`; the remaining platform and
  security gates retain their separate owners. No missing board detail link
  was found in the local checkout.
