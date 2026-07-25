---
id: TODO-567
title: Cut over production release paths to Dioxus
severity: CRITICAL
phase: V
priority: P0
status: OPEN
created: 2026-07-25
depends_on: [TODO-566]
---

# TODO-567: Cut Over Production Release Paths to Dioxus

## Why

Certified Dioxus artifacts are still only candidates until repository build, runtime, packaging, installer, updater, CI, release, and operational paths select them by default. The final task must make the Dioxus web-admin and Tauri-free Dioxus desktop application the production surfaces without modifying or deleting the protected Svelte/Tauri references.

## Acceptance

- Make the certified Dioxus web-admin the default embedded and deployable admin artifact through a new Dioxus-owned output path. Do not overwrite, regenerate, delete, or modify `assets/web-admin/`.
- Make the certified Tauri-free Dioxus desktop package the default desktop release artifact for every supported platform.
- Update canonical Rust runtime wiring, Dioxus-owned build and packaging scripts, installers, updater metadata, CI, release workflows, artifact naming, checksums, and documentation to select the exact certified Dioxus outputs.
- Keep `apps/svelte-admin/`, `apps/svelte-desktop/`, `apps/tauri/`, `packages/ui/`, `packages/theme/`, and `assets/web-admin/` byte-identical as explicit non-default reference and rollback surfaces.
- Provide a typed, documented rollback selection that can choose the retained legacy artifact without rebuilding or editing it, and prove rollback does not corrupt state, secrets, configuration, tunnel ownership, or updater metadata.
- Preserve every web and desktop data migration, configuration, authentication, secret, update, installer, service, firewall, tunnel, cleanup, and compatibility contract during first install, upgrade, rollback, and uninstall.
- Produce exact-commit release artifacts and SHA-256 manifests through host-native tooling only. Docker, container images, Compose, and container-owned deployment or test workflows are forbidden.
- Run the web production matrix in a new exact-task directory under `/home/ubuntu/SOFTWARE/QuicFuscate/` on Omega and prove startup, authentication, administration, upgrade, rollback, shutdown, and zero unexpected residue without mutating unrelated host state.
- Run real supported-platform desktop install, first-start, connect, update, rollback, disconnect, shutdown, uninstall, and residue matrices with signed-package checks where release policy requires them.
- Close every open product task, pass TODO consistency and runtime guardrail audits, and make the zero-open register plus exact release evidence the only production-readiness claim.

## Completion Gates

- Selection gate: default web and desktop build, package, installer, updater, CI, and release paths resolve exclusively to certified Dioxus artifacts.
- Compatibility gate: first install, upgrade from the retained legacy release, Dioxus-to-Dioxus update, rollback, and uninstall preserve all supported state and security contracts.
- Release gate: exact-commit native artifacts, signatures where required, names, sizes, and SHA-256 values are reproducible and verified.
- Live gate: isolated Omega web and real native desktop matrices pass, and teardown proves no unexpected process, listener, firewall, route, namespace, service, package, or file residue.
- Protection gate: pre- and post-cutover manifests prove every retained Svelte/Tauri reference and rollback path remains byte-identical.
- Closure gate: the ordered production register has zero open product tasks; repository audits, complete local gates, native gates, release gates, and owning documentation are green and current.

## Sub-Tasks

- [ ] Map every current web and desktop build, runtime, package, installer, updater, CI, release, rollback, and documentation selection point.
- [ ] Switch production defaults atomically to certified Dioxus artifacts through Dioxus-owned and canonical runtime paths.
- [ ] Implement and prove non-destructive legacy rollback selection and state compatibility.
- [ ] Run exact-commit release, upgrade, rollback, native, Omega, teardown, residue, protection, and audit matrices.
- [ ] Flush canonical documentation, archive all completed task details, and close only at zero open product tasks.

## Notes

- The protected legacy sources and bundles remain in the repository unchanged. This task changes selection and release ownership, not their content.
- No Docker, container image, Compose file, or container-owned workflow is allowed.

## Deviations

None.
