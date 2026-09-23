---
id: TODO-1090
title: Enforce the session's commit-provenance instruction prospectively
severity: LOW
phase: M
priority: P3
status: OPEN
created: 2026-09-23
depends_on: []
---

# TODO-1090: Commit provenance instruction

## Why and evidence

The lake-rooster session instructed Devin not to add its attribution, yet
commits `f6a867fb`, `b0aae929` and `22917444` contain Devin attribution.
Those published commits are historical evidence. Rewriting them without an
explicit history-change request risks unrelated collaborators and is outside
this task.

## Target contract

- Record the historical deviation accurately in the task history without
  modifying published commit identities.
- For future agent commits in this repository, the operator's session-level
  attribution preference is applied before commit. Commit messages and
  trailers contain no unwanted assistant attribution; requested human
  attribution remains intact.
- Reuse an existing commit-message validation mechanism if one exists.
  Otherwise add the smallest review/check step that fits the current repo
  workflow; do not introduce broad hook infrastructure for three old commits.

## Implementation and proof

- [ ] Confirm the exact offending message/trailer text and whether each
      commit is on the published branch.
- [ ] Check existing Git hooks and contributor workflow for a suitable
      prospective control; apply the least intrusive option.
- [ ] Validate that a future prohibited attribution is caught and a normal
      requested commit message passes. Document the rule in its owning
      existing guidance, without duplicating policy files.

## Acceptance

- Historical published commits remain byte-identical. The violation and its
  limited remediation are visible in the task history.
- A future commit made under the same instruction has zero unwanted assistant
  attribution; the check rejects a representative prohibited trailer.
