---
description: Add admin HTTP audit logging for sensitive web-admin actions.
---

# Web Admin Audit Logging

## Context
Production admin endpoints should emit concise audit logs for sensitive actions, including the remote address and outcome. This supports operational traceability and incident response.

## Desired Outcome
All state-changing admin HTTP actions emit a clear, single-line audit log entry that includes action, target identifier (if applicable), remote address, and success or failure.

## Scope
- Admin HTTP endpoints: login, logout, kick, block, unblock, reload, config write, qkey, shutdown.
- Server-side logging only. No credential exposure.

## Dependencies
- `src/implementations/server/admin_http.rs`
- Logging output used by existing ops workflow.

## Work Items
- [x] Capture remote address on each request and propagate to handlers.
- [x] Log login success or failure without logging passwords.
- [x] Log each sensitive action with outcome and target id or ip.
- [x] Avoid logging config contents or secrets.

## Acceptance Criteria
- Each action produces a single audit log line.
- No credentials or config contents are logged.
- Logs are consistent and easy to grep.

## Status
- Complete. OK 2026-01-31
