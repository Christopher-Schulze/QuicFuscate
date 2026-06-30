---
id: TODO-439
title: Security audit logging (SIEM-compatible)
severity: HIGH
phase: "G"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-439: Security audit logging (SIEM-compatible)

## Goal
Implement structured JSON audit logging with an immutable, tamper-evident trail (append-only, hash-chained), covering all security-relevant events: authentication, QKey lifecycle, firewall changes, admin actions, config changes, and connection lifecycle. Provide syslog forwarding (RFC 5424) and CEF (Common Event Format) output for SIEM integration, with async buffered writes that never block the hot path.

## Current State (verified against code)

### Existing logging (unstructured, not audit-grade)
- `src/implementations/server/admin_http.rs:950-955` — `log_admin_action()` logs admin actions as plain text: `log::info!("admin action={} detail={} peer={} status=ok", action, detail, peer)`. This is unstructured, not JSON, not tamper-evident, and mixed with general application logs.
- `src/implementations/server/admin_logs.rs:1-80` — `AdminLogBuffer` is an in-memory ring buffer (`VecDeque`) for the admin UI. It stores log lines with timestamp, level, and message. Intentionally memory-only, no disk writes. Not an audit trail.
- `src/optimize/telemetry.rs:1-100` — Telemetry is a collection of `AtomicU64` counters exported as plain text (`export_telemetry_text()`). Counters are not events — they cannot tell you *when* something happened or *who* did it. No structured event log.

### What's missing
- **No structured audit log**: Events are scattered across `log::info!`, `log::warn!` calls throughout the codebase. There is no centralized audit event type, no JSON serialization, no dedicated audit log file.
- **No tamper-evidence**: Logs can be modified or deleted by anyone with filesystem access. No hash chain, no append-only enforcement.
- **No SIEM integration**: No syslog forwarding, no CEF format. SIEMs (Splunk, Elastic, QRadar, Sentinel) cannot ingest QuicFuscate logs without custom parsers.
- **No event taxonomy**: Events are ad-hoc strings. There is no consistent event type, severity, category, or actor model.
- **No log rotation**: The application uses `log` crate macros which go to stdout/stderr. No file-based logging, no rotation, no retention policy.

## Problem Analysis

### Security implications
1. **No audit trail for compliance**: Security-conscious deployments (enterprise, government) require an immutable audit trail of who did what and when. The current logging is neither structured nor tamper-evident.
2. **No breach forensics**: If a QKey is compromised, there is no log of when it was issued, who issued it, when it was revoked, and which connections used it. The `QKeyRegistry` persists key records but not the lifecycle events.
3. **No SIEM integration**: Modern security operations rely on SIEM platforms for correlation, alerting, and compliance reporting. Without structured log output, QuicFuscate is invisible to SIEMs.
4. **Log tampering**: An attacker with server access can modify or delete logs to cover their tracks. Without hash chaining, there is no way to detect tampering.

### Why current state is insufficient
- `log::info!` is for developer debugging, not security auditing. It lacks structure, actor identification, and tamper-evidence.
- The `AdminLogBuffer` is for the admin UI, not for audit. It's in-memory and volatile.
- Telemetry counters are for performance monitoring, not security events.
- There is no dedicated audit log file, no log rotation, no forwarding.

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AuditEvent (typed event)                        │
│  • event_type: AuditEventType (enum)                                │
│  • timestamp: u64 (epoch ms)                                        │
│  • actor: AuditActor (admin user, client IP, system)                │
│  • target: Option<String> (QKey ID, client IP, config path)         │
│  • severity: AuditSeverity (Info, Warning, Critical)                │
│  • category: AuditCategory (Auth, QKey, Firewall, Admin, Config)    │
│  • details: serde_json::Value (event-specific fields)               │
│  • prev_hash: String (SHA-256 of previous event)                    │
│  • this_hash: String (SHA-256 of this event + prev_hash)            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    AuditLogger (async, buffered)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Event Queue  │  │ Hash Chain   │  │ Buffered Writers         │  │
│  │ (mpsc channel│  │ Engine       │  │                          │  │
│  │  capacity    │  │              │  │  ┌────────────────────┐  │  │
│  │  65536)      │  │ • SHA-256    │  │  │ File Writer        │  │  │
│  └──────┬───────┘  │ • prev_hash  │  │  │ (append-only,      │  │  │
│         │          │ • this_hash  │  │  │  O_APPEND, fsync   │  │  │
│         ▼          └──────┬───────┘  │  │  every 1s)         │  │  │
│  ┌──────────────┐         │          │  └────────────────────┘  │  │
│  │ Worker Task  │─────────┼─────────►│  ┌────────────────────┐  │  │
│  │ (single      │         │          │  │ Syslog Writer      │  │  │
│  │  consumer)   │─────────┼─────────►│  │ (RFC 5424 UDP)    │  │  │
│  └──────────────┘         │          │  └────────────────────┘  │  │
│                           │          │  ┌────────────────────┐  │  │
│                           │─────────►│  │ CEF Writer         │  │  │
│                           │          │  │ (for ArcSight,     │  │  │
│                           │          │  │  Splunk, QRadar)   │  │  │
│                           │          │  └────────────────────┘  │  │
│                           │          └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Hash chain design
Each audit event includes `prev_hash` (SHA-256 of the previous event's serialized form) and `this_hash` (SHA-256 of this event's serialized form including `prev_hash`). This creates a tamper-evident chain:

```
Event_1: { ..., prev_hash: "0000...", this_hash: "abc..." }
Event_2: { ..., prev_hash: "abc...", this_hash: "def..." }
Event_3: { ..., prev_hash: "def...", this_hash: "ghi..." }
```

If any event is modified, its `this_hash` changes, which breaks the chain at the next event. If an event is deleted, the chain breaks at the gap. If events are reordered, the `prev_hash` links don't match.

### Append-only enforcement
- Open the audit log file with `O_APPEND` flag — the kernel enforces that writes go to the end of the file.
- Set file permissions `0600` owned by root or the quicfuscate service user.
- On Linux, use `chattr +a` (append-only attribute) for additional kernel-level enforcement (requires root to set, prevents even root from modifying without removing the attribute first).
- Log rotation: when the file reaches a size threshold, close it, create a new file, and archive the old one. The old file's hash chain is frozen — the new file starts with `prev_hash` = last hash of the old file, maintaining continuity.

## Implementation Plan

### Phase 1: Audit event types and serialization
1. Create `src/audit/mod.rs` with the event taxonomy:
   ```rust
   #[derive(Serialize, Deserialize, Clone)]
   pub enum AuditEventType {
       // Authentication
       AuthSuccess, AuthFailure, AuthRejected, AuthTimeout,
       // QKey lifecycle
       QKeyIssued, QKeyRevoked, QKeyRotated, QKeyExpired,
       // Connection lifecycle
       ConnectionAccepted, ConnectionRejected, ConnectionTerminated,
       ConnectionClosed, ConnectionMigrated,
       // Firewall/routing
       FirewallRuleAdded, FirewallRuleRemoved, RoutingConfigChanged,
       // Admin actions
       AdminLogin, AdminLogout, AdminPasswordChanged,
       AdminConfigChanged, AdminQKeyIssued, AdminQKeyRevoked,
       AdminClientKicked, AdminIsolationRuleChanged,
       // Config
       ConfigLoaded, ConfigReloaded, ConfigValidationFailed,
       // System
       ServerStarted, ServerStopped, ServerCrashed,
       PrivilegeDropped, CertReloaded, CertExpired,
   }
   
   #[derive(Serialize, Deserialize, Clone)]
   pub struct AuditEvent {
       pub seq: u64,                    // monotonic sequence number
       pub timestamp: u64,              // epoch milliseconds
       pub event_type: AuditEventType,
       pub severity: AuditSeverity,
       pub category: AuditCategory,
       pub actor: AuditActor,
       pub target: Option<String>,
       pub details: serde_json::Value,
       pub prev_hash: String,
       pub this_hash: String,
   }
   
   #[derive(Serialize, Deserialize, Clone)]
   pub enum AuditActor {
       Admin { user: String, ip: Option<String> },
       Client { ip: String, qkey_id: Option<String> },
       System,
   }
   ```
2. Implement `serde::Serialize` for all types — JSON output with consistent field ordering.
3. Implement hash chain: `this_hash = SHA-256(serialize(event_without_this_hash))`.

### Phase 2: Async audit logger with buffered writes
1. Create `src/audit/logger.rs` with `AuditLogger`:
   ```rust
   pub struct AuditLogger {
       sender: mpsc::UnboundedSender<AuditEvent>,
       handle: JoinHandle<()>,  // worker task handle
   }
   ```
2. `AuditLogger::log(event)` sends event to mpsc channel — non-blocking, returns immediately. If channel is full, drop the event and increment a `AUDIT_DROPPED` counter (never block the hot path).
3. Worker task (single consumer):
   a. Receive events from channel.
   b. Compute hash chain (sequential — each event needs the previous hash).
   c. Serialize to JSON line (one JSON object per line, newline-delimited JSON / NDJSON).
   d. Write to file with `O_APPEND` + buffered writer.
   e. Flush + fsync every 1 second (configurable).
   f. Forward to syslog writer (if configured).
   g. Forward to CEF writer (if configured).
4. Channel capacity: 65536 events. At 1000 events/second, this is 65 seconds of buffer — more than enough for burst handling.

### Phase 3: File writer with rotation
1. Create `src/audit/file_writer.rs`:
   ```rust
   pub struct AuditFileWriter {
       file: File,  // opened with O_APPEND | O_CREAT | O_WRONLY
       path: PathBuf,
       current_size: u64,
       max_size: u64,          // default 100 MB
       rotation_count: u32,    // keep last N rotated files
       last_hash: String,      // for chain continuity across rotations
   }
   ```
2. On write: append JSON line, update `current_size`.
3. On rotation (when `current_size > max_size`):
   a. Flush and close current file.
   b. Rename to `audit-2026-07-23T10-30-00.jsonl.gz` (compress with flate2).
   c. Create new file.
   d. First event in new file has `prev_hash` = last hash from old file.
   e. Delete oldest rotated file if count exceeds `rotation_count`.
4. fsync interval: configurable, default 1 second. Uses `tokio::time::interval`.

### Phase 4: Syslog forwarding (RFC 5424)
1. Create `src/audit/syslog.rs`:
   ```rust
   pub struct SyslogWriter {
       socket: UdpSocket,  // or Unix datagram socket for local syslog
       facility: u8,       // LOG_AUTH = 4, LOG_AUTHPRIV = 10
       hostname: String,
       app_name: String,   // "quicfuscate"
   }
   ```
2. Format event as RFC 5424 syslog message:
   ```
   <priority>version timestamp hostname app-name procid msgid structured-data msg
   ```
3. Structured data (SD) field carries the JSON audit event:
   ```
   <34>1 2026-07-23T10:30:00Z server1 quicfuscate 12345 - [quicfuscate@1 event_type="AuthFailure" seq="42" hash="abc..."] {"event_type":"AuthFailure",...}
   ```
4. Send via UDP to configured syslog server (default port 514) or Unix socket (`/dev/log` on Linux, `/var/run/syslog` on macOS).

### Phase 5: CEF format for SIEM integration
1. Create `src/audit/cef.rs`:
   ```rust
   pub struct CefWriter;
   impl CefWriter {
       pub fn format(event: &AuditEvent) -> String {
           // CEF: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
           // Example: CEF:0|QuicFuscate|VPN|1.0|100|AuthFailure|5|src=10.0.0.1 suser=admin act=login
       }
   }
   ```
2. Map `AuditEventType` to CEF signature IDs (numeric, stable identifiers).
3. Map `AuditSeverity` to CEF severity (0-10 scale).
4. Map event details to CEF extension fields (src, dst, suser, act, rt, etc.).
5. Output via syslog transport (CEF is typically sent over syslog).

### Phase 6: Integration points
1. **Authentication events**: In `src/implementations/server/mod.rs`:
   - `parse_live_server_initial_auth()` (line 1630) → log `AuthRejected` on rejection.
   - `commit_qkey_auth_result()` (line 2761) → log `AuthSuccess` or `AuthFailure`.
   - `enforce_qkey_auth_timeouts()` (line 2741) → log `AuthTimeout`.
2. **QKey lifecycle**: In `src/implementations/server/qkey_registry.rs`:
   - `insert_with_ttl()` → log `QKeyIssued` with actor, QKey ID, TTL.
   - `revoke()` → log `QKeyRevoked` with actor, QKey ID.
3. **Connection lifecycle**: In `src/implementations/server/mod.rs`:
   - `LiveServerState::acquire_client()` → log `ConnectionAccepted`.
   - `close_live_client()` → log `ConnectionTerminated` with reason.
   - `reconcile()` → log `ConnectionClosed` for naturally closed connections.
4. **Admin actions**: In `src/implementations/server/admin_http.rs`:
   - `log_admin_action()` (line 950) → replace with structured `AuditLogger::log()`.
   - Login/logout → `AdminLogin` / `AdminLogout`.
   - Password change → `AdminPasswordChanged`.
5. **Firewall/routing**: In `src/implementations/server/routing.rs`:
   - `setup_iptables()` → log `FirewallRuleAdded` for each rule.
   - `teardown()` → log `FirewallRuleRemoved`.
6. **Config**: In `src/main.rs`:
   - Config load → `ConfigLoaded`.
   - Config reload → `ConfigReloaded`.

### Phase 7: Tamper-evidence verification tool
1. Add `quicfuscate audit verify` CLI subcommand:
   - Reads audit log file(s).
   - Verifies hash chain: each event's `prev_hash` matches previous event's `this_hash`.
   - Reports any breaks in the chain (tampered, deleted, or reordered events).
   - Reports total event count, time span, event type distribution.

## Technology Choices

### Chosen: NDJSON (newline-delimited JSON) for file format
- One JSON object per line. Easy to parse with any JSON library. Easy to grep, jq, or ingest into Splunk/Elastic.
- Alternative: JSON array (single `[]` with all events). Rejected — requires loading entire file into memory to parse. NDJSON is streamable.
- Alternative: protobuf. Rejected — binary, not human-readable, requires schema management. JSON is universally supported by SIEMs.

### Chosen: SHA-256 hash chain for tamper-evidence
- SHA-256 is fast (~500 MB/s on modern CPUs), universally supported, and collision-resistant.
- Each event's hash includes the previous event's hash, creating a chain that is broken by any modification.
- Alternative: Merkle tree. Rejected — more complex, designed for parallel verification. A linear chain is simpler and sufficient for append-only logs.
- Alternative: Blockchain/distributed ledger. Rejected — massive overkill for a single-server audit log.

### Chosen: `mpsc::unbounded_channel` for event queue
- Non-blocking sender — `log()` never blocks the hot path.
- Single consumer — hash chain computation is sequential (each event needs previous hash), so parallelism doesn't help.
- Unbounded capacity — in practice, 65536 events is more than enough. If the channel fills up, the server is under extreme load and dropping audit events is acceptable (with a metric counter).
- Alternative: `mpsc::bounded_channel` with backpressure. Rejected — backpressure would block the hot path, which is unacceptable for a VPN server processing 100K+ packets/second.

### Chosen: RFC 5424 syslog + CEF for SIEM forwarding
- RFC 5424 is the modern syslog standard (replaces RFC 3164). Supported by rsyslog, syslog-ng, journald, and all major SIEMs.
- CEF (Common Event Format) is the de facto standard for SIEM event interchange. Supported by Splunk, IBM QRadar, Micro Focus ArcSight, Microsoft Sentinel, Elastic SIEM.
- Both can be sent over the same syslog UDP transport — CEF is just a different message format in the syslog body.

### Evaluated and rejected
- **OTLP (OpenTelemetry Logs)**: Rejected — adds significant dependency weight (protobuf, gRPC). Syslog + CEF are lighter and more widely supported by traditional SIEMs. OTLP could be added as a future option for cloud-native deployments.
- **Windows Event Log**: Rejected for now — Linux is the primary server platform. Could be added for Windows Server deployments.
- **journald native API**: Rejected — Linux-specific. Syslog works with journald (journald listens on `/dev/log` for syslog messages).

## Stealth/Efficiency Considerations

### Stealth
- **Audit logs are server-internal**: They do not affect the TLS handshake, packet structure, or traffic patterns visible to DPI.
- **Syslog forwarding**: If the syslog server is on the same host (or a private management network), it doesn't generate visible network traffic. If forwarded over the network, use the management interface, not the TUN interface.
- **No client-side audit logging**: Audit events are server-side only. Client behavior is logged as `ConnectionAccepted` / `ConnectionTerminated` events on the server.

### Performance
- **Non-blocking**: `AuditLogger::log()` is a channel send — ~50ns. No I/O on the hot path.
- **Single worker**: One task handles all I/O (file, syslog, CEF). No contention.
- **Buffered writes**: Events are buffered in memory and flushed every 1 second (configurable). This batches fsync calls — 1 fsync/second instead of 1 fsync/event.
- **Hash computation**: SHA-256 of a ~200-byte JSON event is ~100ns. Negligible.
- **Channel capacity**: 65536 events. At 1000 events/second (high for audit), the buffer holds 65 seconds of events. The worker can drain much faster than events are produced.
- **File rotation**: Compression (gzip) happens in a separate task to avoid blocking the writer.

## Testing Plan

### Unit tests
- `AuditEvent` serialization: correct JSON structure, consistent field ordering.
- Hash chain: `this_hash` = SHA-256 of event including `prev_hash`. Modifying any field breaks the chain.
- `AuditLogger::log()`: event is queued, worker processes it, file contains the event.
- Event taxonomy: all `AuditEventType` variants serialize and deserialize correctly.
- CEF formatting: correct CEF syntax, field mapping, severity mapping.
- Syslog formatting: correct RFC 5424 structure, priority calculation, structured data.

### Integration tests
- End-to-end: trigger an auth event → verify it appears in the audit log file with correct hash chain.
- Rotation: write enough events to trigger rotation → verify new file starts with correct `prev_hash` → verify old file is compressed and archived.
- Tamper detection: modify an event in the log file → `audit verify` detects the break.
- Deletion detection: delete an event from the log file → `audit verify` detects the gap.
- Syslog forwarding: start a mock syslog server → trigger events → verify syslog messages received in RFC 5424 format.
- CEF forwarding: verify CEF messages are correctly formatted and parseable by a CEF parser.

### Performance tests
- 10,000 events/second sustained for 60 seconds → verify no events dropped, no hot-path blocking, file size is reasonable.
- Channel full scenario: fill the channel to capacity → verify `AUDIT_DROPPED` counter increments, hot path is not blocked.

## Files to Create/Modify

### New files
- `src/audit/mod.rs` — Module root: `AuditEvent`, `AuditEventType`, `AuditSeverity`, `AuditCategory`, `AuditActor`
- `src/audit/logger.rs` — `AuditLogger` (async, channel-based, non-blocking)
- `src/audit/file_writer.rs` — `AuditFileWriter` (append-only, rotation, hash chain continuity)
- `src/audit/syslog.rs` — `SyslogWriter` (RFC 5424 UDP/Unix socket forwarding)
- `src/audit/cef.rs` — `CefWriter` (Common Event Format for SIEM)
- `src/audit/verify.rs` — Hash chain verification logic for `quicfuscate audit verify`
- `src/audit/cli.rs` — CLI subcommand handlers for `audit verify` / `audit export`
- `tests/audit_lifecycle.rs` — Integration tests for audit logging
- `tests/audit_tamper.rs` — Tamper detection tests

### Modified files
- `src/main.rs` — Add `Audit` subcommand to `Commands` enum; initialize `AuditLogger` in `run_server()`; add `--audit-log` / `--audit-syslog` / `--audit-cef` CLI flags
- `src/implementations/server/mod.rs` — Replace `log::info!` / `log::warn!` calls at auth, connection, and QKey lifecycle points with `AuditLogger::log()`
- `src/implementations/server/admin_http.rs` — Replace `log_admin_action()` with structured `AuditLogger::log()`; log login/logout/password-change
- `src/implementations/server/qkey_registry.rs` — Log `QKeyIssued` on insert, `QKeyRevoked` on revoke, `QKeyExpired` on prune
- `src/implementations/server/routing.rs` — Log `FirewallRuleAdded` / `FirewallRuleRemoved` on setup/teardown
- `src/lib.rs` — Add `pub mod audit;`
- `Cargo.toml` — Add `sha2` (already present), `flate2 = "1"` (for log compression), `chrono = "0.4"` (for RFC 3339 timestamps in syslog)

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Channel full → events dropped | Non-blocking send with drop counter. Alert when `AUDIT_DROPPED > 0`. Increase channel capacity if needed. |
| Hash chain breaks on rotation | New file's first event carries `prev_hash` from old file's last event. `audit verify` checks across files. |
| File I/O failure (disk full) | Log to stderr as fallback. Alert via metrics. Syslog forwarding continues (different destination). |
| Syslog server unreachable | Buffer syslog messages in memory (up to N), retry with backoff. If buffer full, drop and increment counter. |
| Performance impact of fsync | Configurable fsync interval (default 1s). Batch fsync — one per interval, not per event. |
| Audit log grows unbounded | Rotation with max size (default 100MB) and retention count (default 10 files = 1GB max). Configurable. |
| `chattr +a` not available (container) | Detect at startup. If unavailable, rely on file permissions (0600) + O_APPEND. Log warning. |
| CEF field mapping incomplete | Start with core fields (src, dst, suser, act, rt). Extend mapping as SIEM feedback is received. |
| Timezone issues in timestamps | All timestamps are epoch milliseconds (UTC). No timezone ambiguity. Display tools convert to local time. |

## Completion Criteria

- [ ] `AuditEvent` type taxonomy covers all security-relevant events (auth, QKey, connection, firewall, admin, config, system)
- [ ] `AuditLogger::log()` is non-blocking (channel send, no I/O on hot path)
- [ ] Audit log file is NDJSON with hash chain (`prev_hash` / `this_hash` on each event)
- [ ] File is opened with `O_APPEND` and `0600` permissions
- [ ] Log rotation at configurable size threshold with gzip compression and retention
- [ ] Hash chain continuity across rotated files
- [ ] `quicfuscate audit verify` detects tampering, deletion, and reordering
- [ ] Syslog forwarding in RFC 5424 format (UDP and Unix socket)
- [ ] CEF format output for SIEM integration (Splunk, QRadar, ArcSight, Sentinel)
- [ ] All auth events (success, failure, rejection, timeout) are logged with actor and target
- [ ] All QKey events (issued, revoked, rotated, expired) are logged with actor and QKey ID
- [ ] All connection events (accepted, rejected, terminated, closed, migrated) are logged
- [ ] All admin actions (login, logout, password change, config change, QKey management) are logged
- [ ] All firewall/routing changes are logged
- [ ] All config loads/reloads are logged
- [ ] `AUDIT_DROPPED` metric counter tracks dropped events
- [ ] Performance: 10,000 events/second sustained with no hot-path blocking
- [ ] All unit, integration, tamper detection, and performance tests pass
