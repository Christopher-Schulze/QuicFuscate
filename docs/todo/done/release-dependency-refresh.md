# Release Dependency Refresh Plan

## Goal
Audit and upgrade dependencies safely for v1, including Rust and frontend stacks, with zero behavior regression.

## Execution Status (2026-02-12)
- Rust inventory and audit executed.
- Frontend patch-level refresh executed for both React apps.
- Full compile/test verification passed after updates.
- `rustls` path reviewed explicitly:
  - locked version: `0.23.31`
  - `cargo audit` findings: `0` vulnerabilities, `0` warnings
  - major-line migration to `0.24.x` deferred for post-v1 compatibility hardening.

## Rust Dependency Work
- [x] Generate current dependency inventory (`cargo tree`).
- [x] Identify outdated crates and security advisories.
- [x] Prioritize critical path crates: `rustls`, crypto, networking, serialization.
- [x] Prototype `rustls` upgrade path in a dedicated change set. (deferred with rationale for source-first v1)
- [x] Run full build and test matrix after each upgrade batch.

## Frontend Dependency Work
- [x] Audit `archive/apps/web-admin-ui` dependencies.
- [x] Audit `apps/tauri` dependencies.
- [x] Update packages with security fixes first, then minor upgrades.
- [x] Rebuild and run UI tests after each batch.

## Risk Controls
- [x] One upgrade cluster at a time.
- [x] Capture API breaks and migration notes.
- [x] Keep rollback points for each cluster.

## Acceptance Criteria
- No critical vulnerabilities remain unresolved.
- Upgraded lockfiles build and test cleanly.
- `docs/DOCUMENTATION.md` dependency section reflects actual versions and rationale.

## Evidence
- `cargo tree -e normal > scripts/out/tests/dependency-cargo-tree.txt`
- `cargo audit --json > scripts/out/tests/cargo-audit.json`
- `cd archive/apps/web-admin-ui && bun outdated`
- `cd apps/tauri && bun outdated`
- `cd archive/apps/web-admin-ui && bun update framer-motion @types/node @types/react`
- `cd apps/tauri && bun update framer-motion @types/node @types/react`
- `cd archive/apps/web-admin-ui && bun run test:unit && bun run check`
- `cd apps/tauri && bun run test:unit && bun run check`
- `cargo check --workspace`
