---
id: TODO-1141
title: Reconcile Desktop unit-test inventory floor with current registered tests
severity: MEDIUM
phase: S
priority: P1
status: OPEN
created: 2026-09-24
depends_on: []
---

# TODO-1141: Restore Truthful Desktop Unit Inventory Gate

## Why and current evidence

On 2026-09-24, `bun run test:unit` in `apps/svelte-desktop` executed 38/38
test files and 442/442 tests with zero test failures. The source-owned runner
then returned exit 1 because `apps/svelte-desktop/package.json` requires
`--minimum-files=38 --minimum-tests=453`. The 11-test difference is not
explained by the output. Lowering the threshold without checking lost tests
would hide a regression; leaving the stale threshold makes the required
Desktop gate permanently red. TODO-373 and TODO-377 may add tests, but this
inventory issue has its own owner.

## Target contract

The package command must enforce a minimum inventory derived from the
verified current registered suite, with no skipped, excluded, renamed, or
unregistered test silently counted as covered. Identify when and why the
expected 453 became 442 by comparing test file inventories and relevant Git
history; restore unintentionally lost assertions or update the floor only
after proving that the difference is intentional and that equivalent behavior
remains covered. Keep the runner's fail-on-shrink semantics and 38-file floor.
Coordinate the final test floor with TODO-373 and TODO-377 if their new tests
land in the same change window.

## Execution

- [ ] Compare the current Vitest-discovered 38 files and 442 tests with the
      revision that introduced the 453 floor; name the exact missing or
      intentionally removed tests and their behavior.
- [ ] Restore any lost failable test or, if the old count was stale, change
      only the package inventory floor to the verified post-reconciliation
      count with a recorded rationale. Never weaken the runner itself.
- [ ] Run `bun run test:unit` to a green inventory result, then prove the
      runner still exits nonzero when supplied a minimum above the discovered
      count or a deliberately filtered smaller inventory.
- [ ] Update the owning board/detail and any current frontend test-count
      claim. Record command, revision, files/tests discovered, and exit codes.

## Acceptance

- The canonical Desktop unit command exits 0 with all registered tests
  passing and an inventory floor that is no higher than the justified count
  and no lower than the count needed to detect an unintended shrink.
- A deliberate inventory shortfall still exits nonzero. No test is deleted,
  disabled, or rewritten merely to satisfy the floor.
