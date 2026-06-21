# TODO-190: Full UI Revamp - Web Admin and Desktop

## Status
SUPERSEDED - original umbrella plan retained for history; approved work is now tracked concretely in TODO-191 through TODO-199

## Severity
ENHANCEMENT

## Context
Both the Web Admin UI and Desktop UI accumulated significant technical debt, duplication, and accessibility issues. This umbrella TODO originally proposed a coordinated frontend rebuild. Since then, Svelte rebuilds and shared packages were created, but the forensic review showed that the repository never completed the real cutover: React still owns parts of CI, runtime scripts, docs, and release truth.

This TODO is therefore no longer the right execution unit. The approved work is split into concrete remediation items:

- TODO-191: Svelte cutover and React retirement
- TODO-192: build/CI/release truth alignment
- TODO-193: QKey contract repair
- TODO-194: admin credential policy reconciliation
- TODO-195: canonical docs and backlog truth alignment
- TODO-196: XOR product-surface demotion
- TODO-197: Svelte-era test coverage
- TODO-198: Stealth/Brain/FEC ownership audit
- TODO-199: unsafe ROI review

## Root Cause
The two frontend apps were developed independently without a shared UI foundation. Component choices diverged, styling approaches differ, and no shared package enforces consistency. Individual fixes would be point solutions that don't address the architectural problem.

## Resolution
Keep this file as the historical umbrella record only. Execute the work through TODO-191 through TODO-199, where each concrete defect cluster has explicit acceptance criteria and affected files.

## Historical Outcome
- Shared Svelte packages and rebuilds exist.
- Final repository cutover and truth alignment did not happen inside this umbrella item.
- Remaining work moved into TODO-191 through TODO-199.

## Dependencies
- Historical umbrella only. See TODO-191 through TODO-199 for active dependencies.

## Active Successor Items
- `docs/todo/todo-191-svelte-cutover-and-react-retirement.md`
- `docs/todo/todo-192-svelte-build-ci-release-cutover.md`
- `docs/todo/todo-193-qkey-issuance-reveal-import-contract-repair.md`
- `docs/todo/todo-194-admin-credential-policy-reconciliation.md`
- `docs/todo/todo-195-canonical-ui-doc-and-backlog-truth-alignment.md`
- `docs/todo/todo-196-xor-product-surface-demotion.md`
- `docs/todo/todo-197-svelte-admin-desktop-contract-and-e2e-coverage.md`
- `docs/todo/todo-198-stealth-brain-fec-control-ownership-audit.md`
- `docs/todo/todo-199-unsafe-roi-audit-and-selective-safe-replacement.md`
