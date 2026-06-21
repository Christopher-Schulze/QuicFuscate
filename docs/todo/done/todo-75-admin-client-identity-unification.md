# TODO 75: Admin Client Identity Unification

## Scope
- `src/implementations/server/admin.rs`
- `src/implementations/server/session.rs`
- `src/implementations/server/mod.rs`
- `src/main.rs`

## Problem Statement (Audit Evidence, 2026-03-05)
- Admin identity uses `SocketAddr` strings.
  - Evidence: `src/implementations/server/admin.rs:85`, `:118`
- Embedded server runtime already has `SessionId`.
  - Evidence: `src/implementations/server/session.rs:11`, `src/implementations/server/mod.rs:908`

## Objectives
- Define one canonical client identity for admin/runtime operations.

## Work Breakdown
- [x] Choose canonical identity model.
- [x] Align list/kick/status/admin-action flows to it.
- [x] Add identity-contract tests.

## Acceptance Criteria
- [x] Admin/control plane no longer depends on entrypoint-specific identity semantics.

## Progress Notes
- 2026-03-05: Created from deep forensic review.
- 2026-03-08: Completed. `ClientIdentity::Session(SessionId)` is the canonical admin/runtime identity, admin-visible client projection explicitly prefers `session:<id>`, and the live admin kick path is regression-tested against session identity. Legacy remote-address parsing remains as compatibility input only.
