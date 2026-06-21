# Release Security Audit Plan

## Goal
Produce a repeatable release security audit document for v1 that is aligned with the current code and test tooling.

## Scope
- Rust backend and admin HTTP surfaces.
- Desktop Tauri shell and IPC boundaries.
- Web admin UI auth and session flows.
- Build and dependency security controls.

## Deliverables
- A dedicated security-audit section in `docs/DOCUMENTATION.md`.
- A command list with exact audit commands and expected outputs.
- A findings table with severity, impact, owner, status.
- A residual-risk section with explicit acceptance statements.

## Task Breakdown
- [x] Inventory all exposed attack surfaces.
- [x] Map each surface to existing controls in code.
- [x] Run static hardening scripts and capture outputs.
- [x] Run dependency vulnerability scan and capture outputs.
- [x] Validate session/auth/rate-limit/lockout paths with tests.
- [x] Record findings in a single audit table with status.
- [x] Add remediation items into `docs/todo.md` where needed.
- [x] Link final audit section from README and map.

## Evidence Commands
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace --all-targets`
- [x] `./scripts/tests/audits/audit-all-comprehensive.sh`
- [x] `cargo audit` (if installed) or equivalent dependency audit
- [x] `cd archive/apps/web-admin-ui && bun run check`
- [x] `cd apps/tauri && bun run check`

## Execution Snapshot (2026-02-12)
- Clippy and full workspace tests pass.
- Web and desktop UI unit/build checks pass.
- `cargo audit` reported zero vulnerabilities and zero warnings.
- `audit-all-comprehensive.sh` was executed and reported policy findings (unsafe/unwrap counts); this is recorded as accepted residual risk in the v1 security audit snapshot, with follow-up tracked in release hardening TODO streams.

## Acceptance Criteria
- Every critical/high finding is fixed or explicitly deferred with rationale.
- Audit evidence is reproducible from commands in this file.
- Documentation is synced in `docs/DOCUMENTATION.md` and `docs/MAP.md`.
