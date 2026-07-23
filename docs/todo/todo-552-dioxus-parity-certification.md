---
id: TODO-552
title: Certify and package Dioxus web and desktop parity
severity: CRITICAL
phase: U
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-550, TODO-551]
---

# TODO-552: Certify and package Dioxus web and desktop parity

## Why

Separate implementation completion does not prove whole-product parity. The web and desktop variants need one reproducible certification pass over every frozen state, real behavior, accessibility requirement, performance budget, native package, release artifact, and protected-source hash before either can be treated as a production candidate.

## Acceptance

- Invoke and follow `frontend-cr-june26` for every action. Use its iterative browser capture, visual inspection, and fidelity-ledger workflow for the supplied Svelte references; do not introduce a redesign.
- Recompute the protected-path SHA-256 manifest and prove it is identical to TODO-549. Any protected Svelte, Tauri, shared UI/theme, or generated web-admin change fails certification.
- Exercise every web and desktop route/state in the frozen matrix with real application behavior, matching content, viewport/window geometry, data state, focus state, animation phase, reduced-motion mode, platform state, and error condition.
- Maintain at least five concrete fidelity observations per tested screen/state and resolve every unexplained difference in Dioxus code only.
- Require no semantic visual difference, SSIM at least 0.995, and no more than 0.5% changed pixels attributable only to platform rendering or anti-aliasing for each comparison. Averages cannot hide a failing screen.
- Verify keyboard navigation, focus order, screen-reader semantics, contrast, zoom/text scaling, reduced motion, and error announcement with no critical or serious accessibility violation.
- Verify web auth and administration flows plus desktop tunnel, tray, persistence, secret, update, reconnect, privilege, shutdown, and cleanup flows end to end.
- Benchmark startup, interaction latency, idle and active CPU, memory, network transfer, binary/bundle size, and representative long-running behavior against the frozen reference and task budgets.
- Produce reproducible Dioxus web and native desktop release artifacts from the exact reviewed commit, record SHA-256 values, and validate installation/startup/runtime/teardown on required native platforms.
- Verify the web artifact in an isolated Omega runtime under `/home/ubuntu/SOFTWARE/QuicFuscate/` without changing unrelated services, firewall state, routes, packages, or persistent configuration.
- Keep parity certification separate from later improvement work. Styling, information architecture, copy, interaction, or animation improvements require a new future task after this one is complete.

## Completion Gates

- Matrix gate: 100% of frozen web and desktop route/state/viewport combinations have paired evidence, five or more fidelity observations, and passing individual thresholds.
- Functional gate: all real web and native desktop E2E flows, negative paths, accessibility checks, and reduced-motion cases pass.
- Performance gate: every measured budget passes individually; any regression over 5% or a stricter existing limit blocks closure unless removed.
- Artifact gate: exact-commit web and native packages build reproducibly, carry recorded SHA-256 values, and pass install, startup, runtime, update where applicable, shutdown, uninstall, and residue checks.
- Live gate: the isolated Omega web matrix passes and teardown proves no unexpected process, listener, firewall, route, namespace, file, or service residue.
- Protection and truth gate: protected manifests are identical, TODO consistency and runtime guardrail audits pass, and all owning docs contain the final commands, evidence, artifacts, metrics, coverage, and limitations.

## Sub-Tasks

- [ ] Invoke `frontend-cr-june26`, freeze the certification environment, and validate the complete reference and Dioxus evidence matrix.
- [ ] Resolve every fidelity, behavior, accessibility, and performance failure in Dioxus-owned files only.
- [ ] Build and validate exact-commit web and native desktop release artifacts.
- [ ] Execute native and isolated Omega runtime, teardown, residue, and protection proofs.
- [ ] Flush documentation and close only when every individual gate is green.

## Notes

- This task certifies the Dioxus production candidates; it does not delete, modify, or cut over from the existing Svelte/Tauri applications.
- A later improvement phase may use `frontend-cr-june26` for a new design direction only after parity is independently certified and the user explicitly authorizes that separate scope.

## Deviations

None.
