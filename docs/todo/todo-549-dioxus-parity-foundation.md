---
id: TODO-549
title: Lock the parity reference and build the shared Dioxus component system
severity: CRITICAL
phase: U
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-544]
---

# TODO-549: Lock the parity reference and build the shared Dioxus component system

## Why

No active Dioxus UI exists, while the current Svelte web-admin and Svelte/Tauri desktop surfaces are the exact visual and behavioral references. Parity work needs a frozen evidence baseline and one clean Dioxus component system before either product surface is rebuilt. Building pages first would duplicate tokens, variants, motion, state handling, and accessibility behavior.

## Acceptance

- Invoke and follow `frontend-cr-june26` for every action in this task and every downstream Dioxus task. For parity reconstruction, use its screenshot/reference workflow: the current product is the design source, so do not generate or introduce a new visual direction.
- Before implementation, record the exact reference commit and a cryptographic manifest of `apps/svelte-admin/`, `apps/svelte-desktop/`, `apps/tauri/`, `packages/ui/`, `packages/theme/`, and `assets/web-admin/`.
- Treat all protected reference paths as read-only throughout Dioxus work. Do not edit them and do not run generators or build steps that modify their tracked or untracked contents.
- Create all new implementation only under `Dioxus-UI/`; do not revive the historical archived Dioxus experiment and do not create a parallel implementation elsewhere.
- Verify the current stable Dioxus, styling, routing, accessibility, animation, testing, and packaging interfaces from primary sources before dependency selection. Record exact versions and platform constraints in this task before code calls them.
- Reproduce the reference styling with one shared Tailwind CSS configuration and Dioxus-compatible motion layer, preserving exact values and timing while forbidding inline one-offs, contradictory utilities, and page-local override chains.
- Capture every current web-admin and desktop route, viewport, state, copy string, icon, typography rule, color, spacing value, radius, border, shadow, focus treatment, responsive transition, animation, reduced-motion behavior, and accessibility role needed for parity.
- Establish one shared token layer and one source of truth per reusable Dioxus primitive. Variants must be explicit; wrapper-only components, contradictory overrides, page-local token forks, and deep override chains are forbidden.
- Separate pure presentation components from typed application services and state. UI components must not own networking, persistence, tunnel, updater, platform, or secret-management logic.
- Preserve the visible reference exactly. No cleanup, modernization, copy change, interaction redesign, or speculative feature work is part of the parity phase.
- Define the web and desktop capture matrix, functional-state fixtures, fidelity ledger format, performance budgets, and downstream acceptance thresholds before TODO-550 or TODO-551 starts.

## Completion Gates

- Reference gate: the commit, route/state inventory, capture matrix, and SHA-256 manifest are complete, reviewable, and reproducible.
- Structure gate: the Dioxus workspace builds from `Dioxus-UI/`; shared tokens and primitives have failable unit/component tests; no component or token ownership is duplicated.
- Protection gate: pre- and post-task manifests of every protected reference path are identical and `git diff --name-only` reports no protected UI change.
- Quality gate: formatting, linting, tests, accessibility checks, and a production build for the new Dioxus foundation pass using only its own workspace.
- Truth gate: `docs/DOCUMENTATION.md`, `docs/MAP.md`, this detail file, and `docs/todo.md` describe the exact component ownership, reference commit, selected versions, commands, results, and unresolved blockers.

## Sub-Tasks

- [ ] Invoke `frontend-cr-june26`, inspect the live reference surfaces, and lock the reference commit, hashes, routes, viewports, states, and captures.
- [ ] Verify current Dioxus ecosystem signatures and choose the smallest stable dependency set.
- [ ] Define the shared token, component, state, service, animation, accessibility, and test contracts.
- [ ] Create the `Dioxus-UI/` workspace and implement the shared primitives with explicit variants and tests.
- [ ] Run foundation, protection, and documentation gates; close only with exact evidence.

## Notes

- This task authorizes new files only under `Dioxus-UI/` plus required updates to existing owning documentation and task files.
- Existing Svelte and Tauri sources remain the immutable reference during this program. The new Dioxus desktop client may later remove Tauri from its own runtime path, but this task does not modify or remove the existing Tauri application.
- Image generation is intentionally excluded from the parity phase because the current application itself is the supplied visual reference. TODO-563 owns the separate post-parity concept and design-system phase.
- The visual reference and shared Dioxus foundation can be locked immediately after TODO-544 because the protected Svelte/Tauri surfaces are immutable. Functional service contracts must be revalidated against current source before TODO-550 and TODO-551 call them, and TODO-561 must reconcile canonical truth before TODO-552 certification.

## Deviations

None.
