---
description: Web Admin Security Hardening Checklist
---

# Web Admin Security Hardening Checklist

## Scope
Harden the admin UI and HTTP server against misuse, unsafe operations, and accidental destructive actions while preserving usability.

## Authentication & Session
- Require non-empty username and password input; block login when missing.
- Avoid storing credentials in persistent storage unless explicitly configured.
- Never log credentials; redact login payloads in logs.
- Lock admin UI to same-origin by default; no permissive CORS unless explicit.
- Unauthorized responses must show a login prompt, not demo-mode fallback.

## Request Validation
- Enforce max request size in admin HTTP server.
- Validate JSON payload schemas for `kick`, `block`, `unblock`, `config`.
- Reject empty or malformed identifiers.
- Treat empty QKey response as error.

## Sensitive Operations
- Add confirmation flows for:
  - Shutdown
  - Config write
  - Block/Unblock
- Disable sensitive operations in demo mode.

## Network & Transport
- Recommend reverse proxy with TLS for public exposure.
- Optional IP allowlist (future extension) for admin endpoints.

## Error Handling
- Return consistent error messages without leaking internal details.
- UI should display user-friendly errors and log technical details.

## Audit Logging
- Log admin actions with timestamp, endpoint, outcome.
- Include client IP when available (server-side only).

## Audit Findings (2026-01-31)
- Admin web requires username and password when `--admin-web` is set; credentials are validated and a session cookie is issued.
- Config writes validate TOML and schedule reload on success.
- Install/update endpoints have been removed from the admin HTTP API.
- No explicit request body size limit beyond Content-Length; add guardrails if exposed publicly.

## Resolution Notes (2026-01-31)
- Admin HTTP server now rejects oversized payloads with 413.
- UI shows credential prompt on 401/403 and avoids demo fallback for auth failures.

## Acceptance Criteria
- No unsafe action is executed without explicit user confirmation.
- Admin HTTP server rejects oversized or malformed requests.
- UI never exposes credentials or internal error stacks.
