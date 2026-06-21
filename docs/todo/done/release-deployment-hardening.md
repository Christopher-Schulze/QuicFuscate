# Release Deployment Hardening Guide Plan

## Goal
Define a complete hardening guide for production deployment across server, admin UI, and desktop client operations.

## Server Hardening
- [x] Bind admin interface to trusted network only.
- [x] Enforce firewall policy for QUIC and admin ports.
- [x] Lock filesystem permissions for config and state files.
- [x] Configure process user separation and service sandboxing.
- [x] Configure log retention and rotation with least-sensitive content.
- [x] Document backup and restore for config and qkey registry data.

## Admin UI Hardening
- [x] Enforce HTTPS termination and secure headers.
- [x] Verify session cookie flags and CSRF assumptions.
- [x] Document secure password rotation workflow.
- [x] Document IP allow/block operational policy.

## Desktop Hardening
- [x] Validate Tauri allowlist and IPC command exposure.
- [x] Document secure defaults for local state persistence.
- [x] Document safe runtime flags and environment handling.

## Operational Hardening
- [x] Build incident-response checklist.
- [x] Build rollback playbook for bad release.
- [x] Define health checks and smoke tests before go-live.

## Acceptance Criteria
- [x] Hardening guide is integrated into `docs/DOCUMENTATION.md`.
- [x] Every step has verification command or operational check.
- [x] No undocumented production prerequisites remain.

## Completion Note (2026-02-12)
- Deployment hardening guidance is now integrated into `docs/DOCUMENTATION.md` under "Deployment Hardening Guide (v1)" and aligned with source-first v1 release policy.
