---
id: TODO-439
title: "Structured security audit logging"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-439: Structured security audit logging

## Problem

The server has no security audit trail. All logging is debug-level
`env_logger` output (`src/main.rs:990`), which is unstructured,
ephemeral, and not suitable for SIEM (Security Information and Event
Management) ingestion or compliance requirements.

### 1. No structured audit log

The only log-like infrastructure is `AdminLogBuffer`
(`src/implementations/server/admin_logs.rs:1-60`), which is an
in-memory ring buffer for the admin web UI:
```rust
pub struct AdminLogBuffer {
    capacity: usize,
    inner: Mutex<Inner>,
}
```
It stores `AdminLogLine { ts: u64, level: String, msg: String }` —
freeform text, no structured fields, no security event taxonomy. It
is explicitly documented as "intentionally memory-only. No disk
writes." (line 22). There is no persistent, structured, append-only
audit log.

### 2. No security event taxonomy

A grep for `auth_success`, `auth_failure`, `qkey_issued`,
`qkey_revoked`, `killswitch_enabled`, `connection_established`, or
any structured event type across the codebase returns nothing. The
closest existing infrastructure is:
- `Metrics::record_auth_failure` (`src/implementations/server/metrics.rs:80`)
  which increments a counter — no event log.
- `instrumentation::global().server.auth_failure()`
  (`src/instrumentation.rs:156`) — also a counter, no event.
- `close_live_client_for_qkey_auth_failure`
  (`src/implementations/server/mod.rs:1699`) which calls
  `conn.close()` and logs at `warn!` level — no structured record.

None of these produce a queryable, SIEM-compatible audit record with
timestamp, actor IP, QKey ID, event type, and outcome.

### 3. No immutable storage

There is no append-only file, no `chattr +a` (Linux immutable-append
flag), and no log rotation. An attacker who compromises the server
process can modify or delete `env_logger` output. The
`AdminLogBuffer` is in-memory and lost on restart.

### 4. No SIEM-compatible format

`env_logger` produces human-readable text like:
```
[2026-06-30T12:00:00Z WARN  quicfuscate::server] Client close after QKey auth failure for 1.2.3.4: invalid_qkey_auth
```
This is not parseable by SIEM systems (Splunk, Elastic SIEM, QRadar,
Wazuh) without custom grok patterns. There is no CEF (Common Event
Format) or structured JSON output.

## Goal

- A structured JSON audit log (one event per line) is written to a
  configurable file path.
- A defined event taxonomy covers all security-relevant actions.
- The log file is append-only and immutable on Linux (`chattr +a`).
- The format is SIEM-compatible (JSON with well-defined fields, or
  optional CEF format).
- Configuration options: `audit_log_path`, `audit_log_level`.
- Tests verify that performing auth events produces correct audit log
  entries with timestamp, IP, and QKey ID.

## Implementation Plan

### Step 1: Define the audit event taxonomy

**File:** `src/implementations/server/audit.rs` (new)

- Define an `AuditEvent` enum with variants for each security event:
  ```rust
  #[derive(Debug, Clone, Serialize)]
  #[serde(tag = "event_type")]
  pub enum AuditEvent {
      AuthSuccess(AuthSuccessEvent),
      AuthFailure(AuthFailureEvent),
      QKeyIssued(QKeyIssuedEvent),
      QKeyRevoked(QKeyRevokedEvent),
      QKeyExpired(QKeyExpiredEvent),
      QKeyRotated(QKeyRotatedEvent),
      KillSwitchEnabled(KillSwitchEvent),
      KillSwitchDisabled(KillSwitchEvent),
      ConnectionEstablished(ConnectionEvent),
      ConnectionClosed(ConnectionEvent),
      ConnectionTerminatedByAdmin(ConnectionTerminatedEvent),
      FirewallRuleChange(FirewallRuleEvent),
  }
  ```
- Define per-event structs with common fields:
  ```rust
  pub struct AuditEventCommon {
      pub timestamp: String,       // ISO 8601 UTC
      pub event_id: String,        // UUID v4
      pub source: String,          // "quicfuscate-server" or "quicfuscate-client"
      pub severity: AuditSeverity, // Info, Warning, Critical
  }
  ```
- Per-event payload structs:
  ```rust
  pub struct AuthSuccessEvent {
      pub common: AuditEventCommon,
      pub client_ip: String,
      pub qkey_id: String,
      pub session_id: String,
  }
  pub struct AuthFailureEvent {
      pub common: AuditEventCommon,
      pub client_ip: String,
      pub qkey_id: Option<String>,
      pub reason: String,
  }
  pub struct QKeyRevokedEvent {
      pub common: AuditEventCommon,
      pub qkey_id: String,
      pub revoked_by: String,      // admin user or "system"
      pub connections_terminated: u32,
  }
  // ... etc for each variant
  ```

### Step 2: Implement the audit logger

**File:** `src/implementations/server/audit.rs`

- Create an `AuditLogger` struct:
  ```rust
  pub struct AuditLogger {
      file: Mutex<std::fs::File>,
      path: PathBuf,
      format: AuditFormat,  // Json or Cef
      immutable: bool,      // whether chattr +a was applied
  }
  ```
- `AuditLogger::new(path: &Path, format: AuditFormat) -> Result<Self>`:
  - Opens the file in append mode (`OpenOptions::new().append(true).create(true)`).
  - On Linux, if running as root, applies `chattr +a` to make the
    file append-only (immutable against deletion/modification):
    ```rust
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } == 0 {
        Command::new("chattr").arg("+a").arg(&path).status()?;
    }
    ```
  - If `chattr` fails (e.g. filesystem doesn't support it), log a
    warning but continue.
- `AuditLogger::log(&self, event: AuditEvent)`:
  - Serializes the event as JSON (one line, newline-terminated) or
    CEF string.
  - Writes to the file with a `Mutex` lock.
  - Flushes after each write (to ensure durability).

### Step 3: Add audit configuration

**File:** `src/engine/config.rs`, `src/implementations/server/mod.rs`

- Add to `ServerConfig` (`src/implementations/server/mod.rs:104`):
  ```rust
  pub audit_log_path: Option<PathBuf>,    // default: /var/log/quicfuscate/audit.log
  pub audit_log_level: AuditLogLevel,     // default: Info
  pub audit_log_format: AuditFormat,      // default: Json
  pub audit_log_immutable: bool,          // default: true (Linux only)
  ```
- Define `AuditLogLevel`:
  ```rust
  pub enum AuditLogLevel {
      Off,
      Info,      // AuthSuccess, QKeyIssued, ConnectionEstablished, etc.
      Warning,   // AuthFailure, QKeyExpired
      Critical,  // QKeyRevoked, KillSwitchEnabled, ConnectionTerminatedByAdmin
  }
  ```
  Events below the configured level are not logged.
- Add parsing in the config loader for `[audit]` section:
  ```toml
  [audit]
  path = "/var/log/quicfuscate/audit.log"
  level = "info"
  format = "json"
  immutable = true
  ```

### Step 4: Wire audit events into the server

**File:** `src/implementations/server/mod.rs`

- Create a global `AuditLogger` instance (similar to how
  `AdminLogBuffer` is global in `src/main.rs:984`).
- Emit events at the following call sites:

  | Event | Call site | File:Line |
  |-------|-----------|-----------|
  | `AuthSuccess` | After `QKeyHeaderAuthOutcome::Authenticated` | `mod.rs:1978` |
  | `AuthFailure` | In `close_live_client_for_qkey_auth_failure` | `mod.rs:1699` |
  | `QKeyIssued` | In `issue_unix_admin_qkey` / `issue_http_admin_qkey` | `mod.rs:1116, 1127` |
  | `QKeyRevoked` | In admin revoke action (TODO-436 Step 7) | `admin.rs` |
  | `QKeyExpired` | In `QKeyRegistry::prune_expired` | `qkey_registry.rs:250` |
  | `QKeyRotated` | In `QKeyRotationScheduler` (TODO-436 Step 3) | `qkey_rotation.rs` |
  | `ConnectionEstablished` | In `build_live_server_client_init` after `log::info!("New client connected")` | `mod.rs:2059` |
  | `ConnectionClosed` | In session removal / connection close | `mod.rs:2230` (remove path) |
  | `ConnectionTerminatedByAdmin` | In `revoke_and_terminate` (TODO-436) | `mod.rs` |
  | `FirewallRuleChange` | In `RoutingManager::setup` / `teardown` | `routing.rs:59, 82` |

- Each event includes the client IP (from `remote_addr`), QKey ID
  (from `QKeyAuthState` after TODO-436 Step 5), session ID, and
  timestamp.

### Step 5: Wire audit events into the client kill switch

**File:** `src/implementations/client/killswitch.rs`

- Emit `KillSwitchEnabled` in `KillSwitch::enable` (line 41) after
  `self.backend.block_traffic()`.
- Emit `KillSwitchDisabled` in `KillSwitch::disable` (line 51) after
  `self.backend.allow_traffic()`.
- The client audit logger writes to a local file (e.g.
  `/var/log/quicfuscate-client/audit.log` on Linux,
  `~/Library/Logs/QuicFuscate/audit.log` on macOS).

### Step 6: Add CEF format support (optional)

**File:** `src/implementations/server/audit.rs`

- Implement `AuditFormat::Cef` which serializes events as:
  ```
  CEF:0|QuicFuscate|Server|1.0|100|AuthSuccess|5|ts=2026-06-30T12:00:00Z src=1.2.3.4 qkey_id=abc123 session=Session-42
  ```
  CEF fields: `suser` (QKey ID), `src` (client IP), `act` (event
  type), `rt` (timestamp as epoch ms).
- This allows direct ingestion into Splunk, QRadar, and other SIEM
  systems that natively parse CEF.

### Step 7: Tests

**File:** `src/implementations/server/audit.rs` (inline tests),
`tests/audit_log_test.rs` (new)

- Unit test: `AuditLogger::log(AuthSuccess)` writes a valid JSON line
  to the file. Parse the line and verify `event_type`, `timestamp`,
  `client_ip`, `qkey_id` fields.
- Unit test: `AuditLogger::log(AuthFailure)` with `AuditLogLevel::Off`
  does not write to the file.
- Unit test: Multiple events produce multiple lines (one per event).
- Unit test: CEF format produces a valid CEF string starting with
  `CEF:0|`.
- Integration test: Start the server, connect a client with a valid
  QKey. Verify the audit log contains `AuthSuccess` and
  `ConnectionEstablished` entries with the correct client IP and QKey
  ID.
- Integration test: Connect with an invalid QKey. Verify the audit
  log contains `AuthFailure` with the reason.
- Integration test: Revoke a QKey via admin API. Verify the audit log
  contains `QKeyRevoked` with `revoked_by` and
  `connections_terminated` fields.
- Integration test (Linux, requires root): Verify `chattr +a` is
  applied to the audit log file and the file cannot be deleted
  (`rm` fails with "Operation not permitted").

## Files to Modify/Create

- `src/implementations/server/audit.rs` — **new**: `AuditEvent` enum,
  `AuditLogger`, JSON/CEF serialization, `chattr +a`
- `src/implementations/server/mod.rs` — create global `AuditLogger`,
  emit events at auth/connect/disconnect/revoke call sites
- `src/implementations/server/admin.rs` — emit `QKeyIssued` /
  `QKeyRevoked` events
- `src/implementations/server/qkey_registry.rs` — emit `QKeyExpired`
  in `prune_expired`
- `src/implementations/server/routing.rs` — emit
  `FirewallRuleChange` on setup/teardown
- `src/implementations/client/killswitch.rs` — emit
  `KillSwitchEnabled` / `KillSwitchDisabled`
- `src/engine/config.rs` — add audit config fields
- `tests/audit_log_test.rs` — **new**: integration tests

## Acceptance Criteria

- [ ] `AuditEvent` enum covers all 11 event types: `auth_success`,
      `auth_failure`, `qkey_issued`, `qkey_revoked`, `qkey_expired`,
      `qkey_rotated`, `killswitch_enabled`, `killswitch_disabled`,
      `connection_established`, `connection_closed`,
      `connection_terminated_by_admin`, `firewall_rule_change`.
- [ ] Audit log is written as structured JSON (one event per line).
- [ ] Each event contains `timestamp` (ISO 8601), `event_id` (UUID),
      `source`, `severity`, and event-specific fields (`client_ip`,
      `qkey_id`, `session_id`, etc.).
- [ ] Audit log file is append-only on Linux (`chattr +a` applied
      when running as root).
- [ ] `audit_log_path`, `audit_log_level`, `audit_log_format` are
      configurable.
- [ ] CEF format is available as an alternative to JSON.
- [ ] `AuditLogLevel::Off` disables all audit logging.
- [ ] Integration test: auth events produce correct audit log entries
      with timestamp, IP, and QKey ID.
- [ ] Integration test: QKey revocation produces an audit entry with
      `connections_terminated` count.
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Audit log write per event | < 1 ms | `write_all` + `flush` on append-only file |
| Audit log disk space | ~200 bytes/event | JSON line with common + event-specific fields |
| Events per second (peak) | 1000 | Mutex on file handle; consider buffered writes for high throughput |
| `chattr +a` on startup | < 50 ms | One-time `chattr` command |
| Memory for `AuditLogger` | < 1 KB | File handle + Mutex + config fields |
