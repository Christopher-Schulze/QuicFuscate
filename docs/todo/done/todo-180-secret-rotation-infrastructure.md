# TODO-180: Secret Rotation Infrastructure

## Status
DONE - All three pillars implemented:
1. QKey TTL: Already had expiry fields; enhanced with detailed expiry logging (id, name, overdue_secs) and summary log in prune_expired(). Configurable via TOML `[secret_rotation].qkey_default_ttl_secs`.
2. TLS cert rotation: New polling-based hot-reload module (`tls_reload.rs`). Monitors cert/key file modification timestamps, validates PEM before applying, logs fingerprint changes. No external dependency (no `notify` crate - uses mtime polling instead).
3. Admin password expiry: `AdminAuth` now tracks `password_changed_at` and `password_max_age_days`. Login endpoint checks expiry status (Ok/Warning/GracePeriod/Expired), returns status in JSON response, hard-rejects at 2x max_age. Persisted in `admin-auth.json`.
4. Config: New `[secret_rotation]` TOML section with all three knobs. All default to 0 (disabled) for backward compatibility. Validation enforces sane bounds.
5. Tests: 17 new tests covering config validation, TOML parsing, password expiry lifecycle, TLS reload edge cases.

## Severity
MEDIUM

## Context
There is no secret rotation mechanism for any credential type in the system. QKey tokens have no TTL enforcement - once issued, they remain valid indefinitely. TLS certificates have no rotation hooks - expired certs require manual replacement and restart. Admin passwords have no expiry policy.

- `src/engine/qkey.rs`: QKey tokens issued without TTL field or expiry check
- `src/qftls.rs`: TLS cert loaded at startup, no rotation watcher
- `src/implementations/server/admin.rs`: admin auth has no password expiry
- `config/admin-auth.json`: static credentials with no rotation metadata

## Root Cause
Security credential lifecycle management was not implemented. Initial focus was on functionality (auth works) without addressing operational security (credentials must rotate).

## Fix Plan
1. **QKey TTL enforcement:**
   - Add `issued_at` and `ttl_seconds` fields to QKey token structure
   - Validate TTL on every authentication check in `src/implementations/server/qkey_registry.rs`
   - Auto-expire tokens past TTL, log expiry events
   - Default TTL: 24 hours, configurable via config
2. **TLS certificate rotation:**
   - Add file watcher (notify crate) on TLS cert/key paths
   - On file change: reload cert into rustls config without restart
   - Log cert rotation events with old/new cert fingerprints
3. **Admin password expiry:**
   - Add `created_at` and `max_age_days` to admin auth config
   - Warn in admin UI when password approaching expiry
   - Force password change on expiry
4. Add configuration section for rotation policies in `config/quicfuscate.toml`

## Acceptance Criteria
- QKey tokens have configurable TTL, expired tokens rejected
- TLS certificates reload without server restart on file change
- Admin passwords have configurable expiry with UI warning
- All rotation events logged with tracing
- Configuration documented

## Dependencies
- `notify` crate for file watching (TLS rotation)
- todo-120 (QKey plaintext on disk) - complementary but independent

## Affected Files
- `src/engine/qkey.rs`
- `src/implementations/server/qkey_registry.rs`
- `src/qftls.rs`
- `src/implementations/server/admin.rs`
- `config/quicfuscate.toml`
- `config/admin-auth.json`
- `docs/documentation.md`
