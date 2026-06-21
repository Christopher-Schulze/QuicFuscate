# TODO-214: Weak Local Admin Defaults Documentation and Operator Override Guide

## Status
**COMPLETED - 2026-03-17**

## Severity
**MEDIUM**

## Context
The local helper scripts intentionally allow weak admin defaults for fast local iteration. That behavior is deliberate, but it must be documented clearly as a dev-only convenience, with exact override instructions and no new UI surface.

## Objective
Keep weak local admin defaults as an explicit, documented local-dev behavior and provide precise operator override guidance.

## Scope
- Local helper scripts that set weak defaults.
- Canonical operator/developer docs.
- Exact file and flag references for changing the behavior.
- No new frontend/admin UI settings.

## Detailed Work Plan
1. Inventory every helper script that enables weak local defaults.
2. Document the exact flags and environment variables involved.
3. Document where operators change those values.
4. Distinguish local-dev convenience from real deployment posture.
5. Re-check docs for consistency after the credential policy converges to 4.

## Tracking Checklist
- [x] Weak-default scripts inventoried.
- [x] Exact override points documented.
- [x] Dev-only semantics made explicit.
- [x] No UI work added.
- [x] Docs rechecked after credential-policy update.

## Acceptance Criteria
- Operators can find exactly where to change local weak defaults.
- The docs make it clear that the behavior is intentional and local-dev-focused.
- No new UI configuration surface is introduced.

## Dependencies
- TODO-213
- TODO-219

## Affected Files
- `scripts/utils/util-run-local-admin-web.sh`
- `scripts/utils/util-run-local-ui.sh`
- `docs/DOCUMENTATION.md`
- `docs/troubleshooting.md`

## Completion Notes
- Documented that `scripts/utils/util-run-local-admin-web.sh` and `scripts/utils/util-run-local-ui.sh` intentionally run with `QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1` and `admin / 123` for loopback-focused local development.
- Added exact operator override guidance in `docs/DOCUMENTATION.md` and `docs/troubleshooting.md`: change the helper command line directly or start the server manually with custom `--admin-web-user` and `--admin-web-password`.
- Kept the behavior out of the product UI surface and aligned the wording with the canonical 4-character password policy.
