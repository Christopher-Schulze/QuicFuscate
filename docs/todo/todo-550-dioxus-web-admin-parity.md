---
id: TODO-550
title: Rebuild the web admin in Dioxus with exact parity
severity: CRITICAL
phase: U
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-525, TODO-529, TODO-531, TODO-538, TODO-539, TODO-540, TODO-549]
---

# TODO-550: Rebuild the web admin in Dioxus with exact parity

## Why

The production web-admin needs a Dioxus implementation that consumes the stabilized admin contracts without changing the current Svelte reference. Exact parity must include real authentication, failure states, data refresh, configuration, one-time secret display, logs, responsive behavior, and motion rather than a static visual shell.

## Acceptance

- Invoke and follow `frontend-cr-june26` for every action. Use its reference-reconstruction workflow with current web-admin captures; do not redesign, reinterpret, or generate a new visual concept.
- Implement the web-admin only inside the shared `Dioxus-UI/` workspace from TODO-549, using its tokens, primitives, variants, state boundary, accessibility contract, and fidelity ledger.
- Keep `apps/svelte-admin/`, `apps/svelte-desktop/`, `apps/tauri/`, `packages/ui/`, `packages/theme/`, and `assets/web-admin/` byte-identical and use them only as read-only evidence.
- Reproduce every current route, navigation state, viewport, loading state, empty state, success state, validation state, authorization state, network failure, server failure, copy string, icon, spacing, radius, shadow, focus state, transition, and reduced-motion behavior.
- Use one component source for shell, navigation, cards, forms, fields, controls, tables, dialogs, toasts, badges, logs, and status visualization. Page-local visual forks and override chains are forbidden.
- Bind to the real admin HTTP surface through one typed client boundary. Preserve login, forced-password-change, logout, CSRF, QKey creation/revocation and one-time reveal, client/block management, configuration, status, logs, refresh, timeout, and error semantics.
- Keep secrets out of URLs, logs, persistent browser storage, debug output, and capture artifacts. Clear one-time secret state when its owning view closes or expires.
- Match the current responsive layouts at every reference breakpoint and retain keyboard, focus, screen-reader, contrast, and reduced-motion behavior.
- Add failable component, contract, browser-flow, authentication, authorization, error, refresh, and secret-lifecycle tests against real application boundaries.
- Meet or beat the reference interaction-latency, startup, memory, and transfer-size baselines without changing visible behavior.

## Completion Gates

- Functional gate: every inventoried web-admin route and state passes its real typed-client flow, including negative auth, CSRF, timeout, malformed-response, and server-unavailable cases.
- Fidelity gate: every required viewport/state pair has reference and Dioxus captures, a completed fidelity ledger, no unexplained semantic difference, SSIM at least 0.995, and no more than 0.5% anti-aliasing-only pixel variance.
- Accessibility gate: automated checks and manual keyboard/focus/reduced-motion checks pass with no critical or serious violation.
- Performance gate: measured startup, interaction latency, memory, and transferred assets are no worse than the frozen reference by more than 5%, unless a stricter existing budget applies.
- Protection and build gate: all protected-path hashes remain identical; Dioxus formatting, linting, tests, browser flows, and production web build pass without invoking a Svelte build.
- Truth gate: architecture, API ownership, route/state coverage, commands, artifacts, metrics, and limitations are flushed to the owning documentation and task files.

## Sub-Tasks

- [ ] Invoke `frontend-cr-june26` and complete the web-admin route, state, behavior, accessibility, and capture ledger from the frozen reference.
- [ ] Implement the typed admin client, session boundary, error model, and secret lifecycle.
- [ ] Build every web-admin surface from the shared Dioxus component system without local visual forks.
- [ ] Add real component, contract, browser-flow, accessibility, fidelity, and performance gates.
- [ ] Run protection and production-build gates; flush documentation and close only with exact evidence.

## Notes

- Browser inspection and captures must use the active reference application at the frozen commit. Compare matching viewports and states, not isolated components with invented data.
- This task does not replace or delete the existing Svelte web-admin. Packaging or traffic cutover belongs to TODO-552 after parity is independently proven.

## Deviations

None.
