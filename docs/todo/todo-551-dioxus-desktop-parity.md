---
id: TODO-551
title: Rebuild the desktop client in Dioxus with exact parity
severity: CRITICAL
phase: U
priority: P0
status: OPEN
created: 2026-07-23
depends_on: [TODO-527, TODO-528, TODO-530, TODO-532, TODO-533, TODO-537, TODO-541, TODO-542, TODO-543, TODO-544, TODO-545, TODO-548, TODO-549]
---

# TODO-551: Rebuild the desktop client in Dioxus with exact parity

## Why

The current desktop client is a Svelte frontend hosted by Tauri. The new Dioxus desktop client should connect to QuicFuscate through typed Rust boundaries directly, eliminating Tauri from the new runtime path while keeping the existing application untouched as the parity reference and rollback surface.

## Acceptance

- Invoke and follow `frontend-cr-june26` for every action. Use its screenshot/reference reconstruction workflow with the current desktop client; do not redesign or introduce new visual decisions.
- Implement the desktop client only inside `Dioxus-UI/`, reusing the shared tokens, primitives, variants, motion, state, accessibility, and fidelity contracts from TODO-549.
- Keep `apps/svelte-admin/`, `apps/svelte-desktop/`, `apps/tauri/`, `packages/ui/`, `packages/theme/`, and `assets/web-admin/` byte-identical. Do not remove, refactor, migrate, regenerate, or otherwise alter the existing Tauri application.
- Build the new desktop binary with Dioxus Desktop and typed Rust services, without a Tauri dependency in the new application. Read actual Dioxus and QuicFuscate signatures before selecting or calling integration APIs.
- Reproduce the complete current 900x670 surface and every relevant route, dialog, menu, tray state, loading state, disconnected/connecting/connected state, error state, settings state, log state, update state, copy string, icon, spacing, radius, shadow, focus state, transition, animation, and reduced-motion behavior.
- Keep UI components pure. Typed services must own tunnel lifecycle, privileged operations, persistence, secret storage, configuration, logs, updates, startup behavior, tray behavior, platform notifications, and shutdown.
- Preserve or strengthen all backend semantics after the transport, cleanup, firewall, installer, and platform tasks stabilize. Do not hide an unavailable feature behind a visual fake or static placeholder.
- Prove startup, connection, reconnect, cancel, disconnect, crash recovery, update, persistence, secret handling, tray, window, shutdown, and privileged failure behavior through real boundaries.
- Implement native platform adapters only where the new Dioxus runtime needs them; avoid duplicate domain logic and route all reusable behavior through existing Rust owners.
- Meet exact visual parity and meet or beat reference startup, idle memory, interaction latency, CPU, and packaged-size budgets without changing visible behavior.

## Completion Gates

- Architecture gate: dependency inspection proves the new desktop binary has no Tauri dependency and no duplicated protocol, persistence, secret, update, firewall, or tunnel domain owner.
- Functional gate: native tests cover all inventoried desktop states and lifecycle transitions, including privilege denial, malformed configuration, daemon loss, reconnect, update failure, and clean shutdown.
- Fidelity gate: every required state at the exact reference window size has paired captures, a completed fidelity ledger, no unexplained semantic difference, SSIM at least 0.995, and no more than 0.5% anti-aliasing-only pixel variance.
- Native gate: supported macOS and Windows builds, tests, signing/package checks, tray/window behavior, privileged integration, and cleanup pass on real native runners; Linux behavior is proven where the product contract includes it.
- Performance gate: startup, idle memory, interaction latency, CPU, and packaged size are no worse than the frozen reference by more than 5%, unless a stricter existing budget applies.
- Protection and truth gate: all protected-path hashes remain identical and the owning documentation records exact architecture, platform coverage, commands, artifacts, metrics, and blockers.

## Sub-Tasks

- [ ] Invoke `frontend-cr-june26` and complete the desktop state, behavior, accessibility, motion, and capture ledger from the frozen reference.
- [ ] Define the direct typed Rust service boundary and prove the new dependency graph excludes Tauri and duplicate domain logic.
- [ ] Build every desktop surface from the shared Dioxus component system with exact visual and behavioral parity.
- [ ] Implement and test native window, tray, lifecycle, persistence, secret, update, tunnel, and failure integration.
- [ ] Run native, fidelity, performance, protection, and documentation gates; close only with exact evidence.

## Notes

- “No Tauri” applies to the new Dioxus desktop runtime only. The existing Svelte/Tauri application stays intact until a later explicit product decision after TODO-552.
- Feature adjustments are allowed only when required to expose already-completed backend contracts correctly. They must preserve the current visible reference during the parity phase and cannot become speculative UI improvements.

## Deviations

None.
