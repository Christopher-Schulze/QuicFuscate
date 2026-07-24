---
id: TODO-561
title: Reconcile canonical documentation and evidence-state truth
severity: CRITICAL
phase: S
priority: P0
status: OPEN
created: 2026-07-24
depends_on: [TODO-525, TODO-526, TODO-527, TODO-528, TODO-529, TODO-530, TODO-531, TODO-533, TODO-537, TODO-538, TODO-539, TODO-540, TODO-541, TODO-542, TODO-543, TODO-544, TODO-548, TODO-556, TODO-557, TODO-558, TODO-559, TODO-560]
---

# TODO-561: Reconcile Canonical Documentation and Evidence-State Truth

## Why

The ordered production register is current, but canonical documentation still contains drift-prone status prose and direct contradictions. Verified examples include `docs/DOCUMENTATION.md` describing TODO-519 as both completed with native signed Windows evidence and still open or not native-proven, retaining an older release checkpoint as "under CI validation," and mixing historical snapshots with current platform claims. If these contradictions remain after the implementation queue closes, a new agent or operator cannot distinguish present product truth from historical evidence.

This is a bounded documentation-integrity deliverable, not a production-readiness umbrella. It owns only canonical status, evidence, link, command, platform, and architecture truth after the non-Dioxus implementation contracts stabilize.

## Acceptance

- Exhaustively inventory current-state and historical-state claims in `docs/DOCUMENTATION.md`, `docs/MAP.md`, `README.md`, `SECURITY.md`, `docs/CONTRIBUTING.md`, configuration comments, installer/service documentation, and active task references.
- Derive current task status from `docs/todo.md` plus detail-file frontmatter. No canonical current-state sentence may mark a completed task open, an open task complete, or use a historical checkpoint as the latest proof.
- Reconcile release, updater, native-platform, artifact, installer, firewall, FEC, transport, security, and Dioxus-prerequisite claims against the final exact commits, run IDs, artifact SHA-256 values, and retained task evidence.
- Preserve useful historical measurements and decisions, but label snapshots with their commit/date/task boundary so they cannot be mistaken for the current contract.
- Remove volatile totals and "latest" claims unless an existing deterministic owner regenerates or verifies them. Stable commands, invariants, supported platforms, and evidence pointers remain canonical.
- Verify every referenced path, task detail, archived detail, script, configuration key, workflow, command, anchor, and section link exists and uses current casing.
- Keep one owner per topic: `docs/DOCUMENTATION.md` for product/operation truth, `docs/MAP.md` for architecture/wiring, and `docs/todo.md` plus detail files for work/evidence status. Remove conflicting duplication or replace it with a direct canonical pointer.
- Add a deterministic documentation-status audit only if existing checks cannot detect open/completed-task contradictions, broken task links, forbidden stale status phrases, or protected-path drift. The audit must be narrow, failable, and wired into the existing audit/CI structure without a parallel documentation system.
- Make no product, runtime, dependency, release-packaging, Svelte/Tauri UI, Dioxus UI, or server change under this task. Workflow edits are limited to invoking the narrow documentation audit if that audit is required and may not change build, test, artifact, permission, or publication semantics. Any newly discovered product gap becomes its own new open task and blocks this task's closure.
- Pass documentation/link/status checks, TODO consistency, runtime guardrails, diff integrity, and protected UI hash/diff checks on the exact documentation commit.

## Completion Gates

- Status-truth gate: an exhaustive machine-assisted scan finds zero current-state contradictions across every OPEN, DONE, SCRAP, SUPERSEDED, and DEFERRED task referenced by canonical docs.
- Evidence gate: every current release, native-platform, live-runtime, benchmark, and security claim names its exact retained evidence boundary or is qualified as historical/informational.
- Ownership gate: product, architecture, and task truth each have one canonical owner; duplicate current-state prose is removed or converted to stable pointers without losing historical evidence.
- Reference gate: every task link, path, command, config key, workflow, anchor, and section reference resolves with exact casing and no protected or archived surface is misrepresented as active.
- Failability gate: if a new audit is required, targeted negative fixtures prove that stale status, broken links, missing detail files, duplicate owners, and protected-path changes fail nonzero.
- Protection gate: manifests and `git diff --name-only` prove `apps/svelte-admin/`, `apps/svelte-desktop/`, `apps/tauri/`, `packages/ui/`, `packages/theme/`, and `assets/web-admin/` are unchanged.
- Closure gate: `git diff --check`, documentation checks, TODO consistency, runtime guardrails, and final self-review pass; this task file and `docs/todo.md` record the exact commands, counts, corrections, limitations, and commit.

## Sub-Tasks

- [ ] Freeze the exact post-TODO-560 commit and generate a claim inventory by owner, task ID, current status, evidence boundary, path, and link.
- [ ] Classify every conflict as stale current-state prose, valid historical snapshot, broken reference, duplicate owner, volatile claim, or newly discovered product gap.
- [ ] Reconcile `docs/DOCUMENTATION.md`, `docs/MAP.md`, root/operator docs, configuration comments, and task references in one atomic documentation pass.
- [ ] Add or extend only the smallest deterministic audit needed to prevent the verified drift classes from recurring.
- [ ] Run negative audit fixtures where applicable, TODO consistency, runtime guardrails, link/path/status checks, diff integrity, and protected-path proof.
- [ ] Record the final claim counts, corrected contradictions, exact evidence pointers, commands, and any newly queued product task before closure.

## Notes

- Verified starting contradictions exist in `docs/DOCUMENTATION.md`: TODO-519 is described as completed with native signed Windows evidence near the release baseline, but later current-state rows still call its Windows updater/signature proof open or pending.
- Primary owners: `docs/DOCUMENTATION.md`, `docs/MAP.md`, `docs/todo.md`, `docs/todo/*.md`, `README.md`, `SECURITY.md`, `docs/CONTRIBUTING.md`, `config/*.toml`, `scripts/install/`, and `.github/workflows/`.
- Execute this after every non-Dioxus production task so one consolidated pass captures their final evidence and avoids repeated broad documentation churn. TODO-549 depends on this clean truth baseline.
- This task cannot close production readiness by itself and must not become a generic final sign-off. Its only deliverable is contradiction-free, evidence-addressable canonical documentation.

## Deviations

None.
