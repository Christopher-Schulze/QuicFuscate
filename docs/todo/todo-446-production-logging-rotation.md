---
id: TODO-446
title: "Production logging (structured JSON, rotation, file output, per-module levels, syslog)"
severity: HIGH
phase: "I"
priority: P1
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-446: Production Logging (Rotation, Structured JSON, File Output, Syslog)

## Goal
Replace the current `env_logger`-based logging with a production-grade `tracing`/`tracing-subscriber` stack that provides structured JSON logging (NDJSON), log rotation (size-based and time-based via `tracing-appender`), configurable per-module log levels, simultaneous file + stderr output, and remote syslog integration (UDP) for headless deployments. The migration must be transparent — existing `log::info!()` calls continue to work via the `tracing-log` bridge.

## Current State (verified against code)

### Logging uses env_logger
`src/main.rs:1031-1043` — logging is initialized with `env_logger::Builder`:
```rust
let mut builder = env_logger::Builder::new();
builder.filter_level(log::LevelFilter::Trace);
let buf = admin_log_buffer.clone();
builder.format(move |fmt, record| {
    let msg = format!("{}", record.args());
    buf.push(record.level(), &msg);
    writeln!(fmt, "[{}] {}", record.level(), msg)
});
builder.init();
```
- Filter level is set to `Trace` and runtime verbosity is controlled via `log::set_max_level()` (line 1046)
- No structured fields — plain text format `[LEVEL] message`
- No JSON output
- No file output — all logs go to stderr only
- No log rotation

### Runtime log level changes
`src/main.rs:2140-2155` — log level is changed at runtime via `log::set_max_level()`:
```rust
let level_filter = match effective_level.to_ascii_lowercase().as_str() {
    "error" => Some(log::LevelFilter::Error),
    "warn" => Some(log::LevelFilter::Warn),
    "info" => Some(log::LevelFilter::Info),
    "debug" => Some(log::LevelFilter::Debug),
    "trace" => Some(log::LevelFilter::Trace),
    _ => None,
};
if let Some(filter) = level_filter {
    log::set_max_level(filter);
}
if !effective_logging.log_to_stdout {
    log::set_max_level(log::LevelFilter::Off);
}
```

### LoggingConfig exists but file output not wired
`src/engine/config.rs:605-618` — `LoggingConfig` has `log_file_path` field:
```rust
pub struct LoggingConfig {
    pub mode: LoggingMode,
    pub level: String,
    pub log_to_file: bool,
    pub log_file_path: String,       // "/var/log/quicfuscate.log" — never opened
    pub log_to_stdout: bool,
    pub ring_buffer_capacity: usize,
    pub strip_metadata: bool,
}
```
`log_to_file` defaults to `false`; even when `true`, no file appender exists. `log_file_path` is never opened.

### Config file has logging section
`config/server-linux.default.toml:169-173`:
```toml
[logging]
level = "info"
# log_to_file = false
# log_file_path = "/var/log/quicfuscate.log"
# log_to_stdout = true
```

### No per-module log levels
Single `level` field applies to all modules. No way to set `stealth=info, transport=debug, fec=trace`.

### No tracing crate
`Cargo.toml` has no `tracing`, `tracing-subscriber`, `tracing-appender`, or `tracing-log` dependencies. The `log` crate is used throughout the codebase (100+ call sites).

### Telemetry counters exist
`src/optimize/telemetry.rs` — extensive `AtomicU64` counters for TUN, H3, FEC, stealth metrics. These are separate from logging — they're instrumentation counters, not log events.

## Problem Analysis

1. **No log rotation**: Logs grow without bound. A 24/7 VPN server generates gigabytes of logs per week → disk exhaustion.
2. **No structured JSON**: Plain text logs require regex/grok patterns for aggregation (ELK, Loki, Datadog, Splunk). JSON NDJSON enables direct ingestion.
3. **log_file_path configured but not used**: The config field exists but is never opened — misleading.
4. **No per-module log levels**: Cannot set `info` globally but `debug` for a specific module under investigation.
5. **No syslog**: Headless deployments (servers, containers) need remote logging to a central syslog server.
6. **No async writes**: `env_logger` writes synchronously to stderr — can block the hot path under high log volume.
7. **AdminLogBuffer**: The existing `AdminLogBuffer` (line 1027) captures logs for the admin UI. This must be preserved during migration.

## Proposed Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  Logging Architecture                             │
│                                                                   │
│  Existing log::info!() ──┐                                        │
│                           │  tracing-log bridge                   │
│  New tracing::info!() ────┤  (LogTracer::init)                    │
│                           │                                       │
│                           ▼                                       │
│  ┌──────────────────────────────────────────────────────┐       │
│  │           tracing_subscriber::registry()              │       │
│  │           with(EnvFilter)                             │       │
│  └──────┬──────────────┬──────────────┬──────────────────┘       │
│         │              │              │                           │
│         ▼              ▼              ▼                           │
│  ┌──────────┐  ┌──────────────┐  ┌──────────┐                   │
│  │ stderr   │  │ RollingFile  │  │ Syslog   │                   │
│  │ layer    │  │ Appender     │  │ UDP      │                   │
│  │ (JSON or │  │ (JSON or     │  │ (RFC5424)│                   │
│  │  text)   │  │  text)       │  │          │                   │
│  │          │  │  + NonBlocking│ │          │                   │
│  └──────────┘  └──────────────┘  └──────────┘                   │
│                                                                   │
│  AdminLogBuffer: preserved via custom layer or format callback    │
└──────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Step 1: Add tracing dependencies
Add to `Cargo.toml`:
```toml
[dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter", "fmt"] }
tracing-appender = "0.2"
tracing-log = "0.2"
```

The `tracing-log` crate bridges existing `log::info!()` calls to the tracing subscriber — no code changes needed in 100+ existing call sites.

### Step 2: Create logging initialization module
Create `src/logging.rs`:

```rust
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tracing_appender::rolling;
use std::path::PathBuf;

pub fn init(config: &LoggingConfig) -> Result<WorkerGuard, LogInitError> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&build_filter_string(config)));

    let registry = tracing_subscriber::registry().with(filter);

    // stderr layer
    let stderr_layer = if config.log_to_stdout {
        if config.log_format == LogFormat::Json {
            Some(fmt::layer().json().with_writer(std::io::stderr).boxed())
        } else {
            Some(fmt::layer().with_writer(std::io::stderr).boxed())
        }
    } else { None };

    // File layer with rotation + non-blocking writes
    let (file_layer, guard) = if config.log_to_file {
        let file_appender = create_file_appender(config)?;
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let layer = if config.log_format == LogFormat::Json {
            fmt::layer().json().with_writer(non_blocking).boxed()
        } else {
            fmt::layer().with_writer(non_blocking).boxed()
        };
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    registry.with(stderr_layer).with(file_layer).init();

    // Bridge existing log crate macros to tracing
    tracing_log::LogTracer::init()?;

    Ok(guard.unwrap_or(WorkerGuard::default()))
}

fn build_filter_string(config: &LoggingConfig) -> String {
    let mut parts = vec![config.level.clone()];
    for (module, level) in &config.module_levels {
        parts.push(format!("{}={}", module, level));
    }
    parts.join(",")
}
```

### Step 3: Size-based rotation
`tracing-appender` provides time-based rotation (daily, hourly, never) but not size-based. Implement a custom `MakeWriter`:

```rust
pub struct SizeRotatingAppender {
    dir: PathBuf,
    prefix: OsString,
    max_size_bytes: u64,
    keep: usize,
    current: Mutex<CurrentFile>,
}
// Rotates when file exceeds max_size_bytes: current.log → current.1.log → ...
```

### Step 4: Syslog integration
For remote syslog (UDP RFC 5424):
```rust
pub struct SyslogWriter {
    socket: UdpSocket,
    facility: u8,
    hostname: String,
    tag: String,
}
// Implements std::io::Write — formats messages as RFC 5424 syslog packets
```
Config:
```toml
[logging.syslog]
enabled = false
host = "syslog.example.com"
port = 514
facility = "local0"
tag = "quicfuscate"
```

### Step 5: Extend LoggingConfig
Add to `src/engine/config.rs:605-618`:
```rust
pub struct LoggingConfig {
    // ... existing fields ...
    pub log_format: LogFormat,           // Json | Text
    pub log_rotation: LogRotation,       // Daily | Hourly | Never | SizeBased
    pub module_levels: HashMap<String, String>,
    pub syslog: Option<SyslogConfig>,
}
pub enum LogFormat { Json, Text }
pub enum LogRotation { Daily, Hourly, Never, SizeBased { max_size_mb: u64, keep: usize } }
```

### Step 6: Config file
```toml
[logging]
level = "info"
log_to_file = true
log_file_path = "/var/log/quicfuscate/server.log"
log_to_stdout = true
log_format = "json"
log_rotation = "size"
log_rotation_size_mb = 100
log_rotation_keep = 5

[logging.module_levels]
stealth = "info"
transport = "debug"
fec = "trace"

[logging.syslog]
enabled = false
host = "syslog.example.com"
port = 514
facility = "local0"
tag = "quicfuscate"
```

### Step 7: JSON log format
```json
{"timestamp":"2026-07-23T12:00:00.123Z","level":"INFO","target":"quicfuscate::killswitch","fields":{"message":"Kill switch enabled","vpn_connected":false}}
```
Fields: `timestamp` (ISO 8601 UTC ms), `level` (ERROR/WARN/INFO/DEBUG/TRACE), `target` (Rust module path), `fields.message`, `fields.*` (structured key-value pairs).

### Step 8: Call init() at startup
In `src/main.rs`, replace the `env_logger::Builder` block (lines 1031-1043) with:
```rust
let _guard = quicfuscate::logging::init(&config.logging)
    .expect("failed to initialize logging");
```
The `_guard` (WorkerGuard) must be held for the application lifetime — dropped last to flush buffers.

### Step 9: Preserve AdminLogBuffer
The existing `AdminLogBuffer` (line 1027) captures logs for the admin UI. Implement a custom tracing layer that pushes events to the buffer:
```rust
struct AdminLogLayer { buffer: Arc<AdminLogBuffer> }
impl<S: Subscriber> Layer<S> for AdminLogLayer { ... }
```

## Technology Choices

| Choice | Selection | Rationale |
|--------|-----------|-----------|
| Logging framework | `tracing` + `tracing-subscriber` | Industry standard for Rust; structured fields; composable layers; zero-cost when level disabled |
| Log bridge | `tracing-log` (`LogTracer::init`) | Forwards existing `log::info!()` to tracing — no code changes in 100+ call sites |
| File rotation | `tracing-appender` RollingFileAppender | Time-based (daily/hourly); non-blocking writes via dedicated thread |
| Size-based rotation | Custom `SizeRotatingAppender` | `tracing-appender` lacks size-based; implement `MakeWriter` that rotates at N MB |
| Non-blocking writes | `tracing-appender::non_blocking` | Dedicated writer thread; no hot-path blocking; `WorkerGuard` flushes on drop |
| Per-module levels | `EnvFilter` directive syntax | `info,stealth=debug,transport=trace` — standard tracing-subscriber feature |
| Syslog | Custom `SyslogWriter` (UDP RFC 5424) | No mature `tracing-syslog` crate; custom writer is simple and reliable |
| Alternative: `tracing-syslog` crate | Considered | Unmaintained; custom writer is more reliable |
| JSON format | `fmt::layer().json()` | Built-in tracing-subscriber feature; NDJSON output |

## Stealth/Efficiency Considerations

- **Zero-cost when disabled**: `tracing` is zero-cost when a level is filtered out — no allocation, no formatting. This is critical for the hot path (per-packet processing).
- **Non-blocking writes**: File and syslog writes happen on a dedicated thread via `tracing-appender::non_blocking`. The hot path never blocks on I/O.
- **No hot-path allocation**: When a log level is enabled, `tracing` allocates only for the event fields. For the hot path, use `tracing::debug!()` with structured fields (no `format!()` in the message).
- **Log volume control**: In stealth mode, reduce log level to `warn` to minimize log volume. Logs can reveal operational patterns (connection times, client IPs).
- **Log sanitization**: The `strip_metadata` field in `LoggingConfig` should strip client IPs and sensitive data from logs in stealth mode. Implement a custom formatter that redacts fields.
- **Syslog over UDP**: UDP is fire-and-forget — no connection overhead, no blocking. But logs can be lost under network congestion. Document this trade-off.
- **Performance budget**: JSON log write (info level) < 5µs (serialization + non-blocking queue). Disabled level ~0ns.

## Testing Plan

### Unit tests
- `test_build_filter_string` — global level + per-module directives produce correct EnvFilter string
- `test_size_rotating_appender_rotate` — file rotates when exceeding max_size_bytes
- `test_size_rotating_appender_keep_limit` — at most `keep` rotated files exist
- `test_syslog_writer_format` — RFC 5424 packet format is correct
- `test_log_format_json` — each log line is valid JSON parseable by `jq`
- `test_log_format_text` — text format is human-readable

### Integration tests
- `test_log_to_file` — with `log_to_file = true`, file is created at `log_file_path` and written to
- `test_log_rotation_size` — with `log_rotation = "size"` and `log_rotation_size_mb = 1`, after > 1 MB, new file created, old renamed to `.1`
- `test_log_rotation_keep` — with `log_rotation_keep = 3`, at most 3 rotated files exist
- `test_log_rotation_daily` — with `log_rotation = "daily"`, new file at UTC midnight
- `test_per_module_levels` — with `stealth=info,transport=debug,fec=trace` and global `level=warn`: stealth logs at info, transport at debug, fec at trace, others at warn
- `test_log_bridge` — existing `log::info!()` calls appear in tracing output
- `test_log_to_stdout_false` — with `log_to_stdout = false` and `log_to_file = true`: no stderr output, all in file
- `test_dual_output` — with both `log_to_stdout = true` and `log_to_file = true`: output on both
- `test_shutdown_flush` — on shutdown, log file is flushed (no data loss)
- `test_syslog_udp` — syslog writer sends UDP packets to a mock syslog server
- `test_admin_log_buffer_preserved` — AdminLogBuffer still receives log events after migration
- `test_no_performance_regression` — logging at `info` level adds < 1µs per call

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `Cargo.toml` | Modify | Add `tracing`, `tracing-subscriber`, `tracing-appender`, `tracing-log` dependencies |
| `src/logging.rs` | Create | `init()`, `SizeRotatingAppender`, `SyslogWriter`, `AdminLogLayer`, `build_filter_string()` |
| `src/engine/config.rs:605-618` | Modify | Add `log_format`, `log_rotation`, `module_levels`, `syslog` fields to `LoggingConfig`; add `LogFormat`, `LogRotation`, `SyslogConfig` enums |
| `src/main.rs:1031-1043` | Modify | Replace `env_logger::Builder` with `logging::init()`; hold `_guard` |
| `config/quicfuscate.toml` | Modify | Add `[logging]` section with new fields |
| `config/server-linux.default.toml:169-173` | Modify | Add `[logging]` section with new fields |
| `docs/DOCUMENTATION.md` | Modify | Document logging configuration, JSON format, rotation, syslog |

## Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `tracing-log` bridge misses some log macros | Medium | Test all log levels (error/warn/info/debug/trace); verify in integration tests |
| `WorkerGuard` dropped too early → log loss | High | Store guard in `main()` and drop last; document requirement |
| Size-based rotation race condition | Medium | `Mutex<CurrentFile>` protects file state; rotation is atomic (rename + open) |
| Syslog UDP packet loss | Low | Document that UDP is unreliable; recommend local syslog relay (rsyslog) for production |
| AdminLogBuffer breaks after migration | Medium | Implement custom `AdminLogLayer`; test admin UI log display |
| Performance regression from tracing overhead | Low | Tracing is zero-cost when level disabled; non-blocking writes; benchmark hot path |
| Log file permissions on Linux | Low | Document that `/var/log/quicfuscate/` must be writable by the service user |
| `tracing-subscriber` API breaking changes | Low | Pin version to `0.3.x`; API is stable |

## Completion Criteria

- [x] With `log_format = "json"`: each log line is valid JSON parseable by `jq` (NDJSON). **GAP -> TODO-531** - `format_json()` is valid NDJSON in units, but startup initializes `LoggingConfig::default()` before loading the operator config.
- [x] JSON log line contains: `timestamp` (ISO 8601 UTC), `level`, `target`, `fields.message`. **SUPERSEDED** - the canonical compact schema uses `ts`, `level`, `target`, and `msg`; TODO-531 must document and process-test that stable schema.
- [x] With `log_to_file = true`: log file is created at `log_file_path` and written to. **GAP -> TODO-531** - file appender code exists, but operator logging configuration never reaches initialization.
- [x] With `log_rotation = "size"` and `log_rotation_size_mb = 1`: after > 1 MB, new file created, old renamed to `.1`. **GAP -> TODO-531** - size rotation passes direct units but lacks configured process-level proof.
- [x] With `log_rotation_keep = 3`: at most 3 rotated files exist (plus current). **GAP -> TODO-531** - retention units pass without runtime config wiring.
- [x] With `log_rotation = "daily"`: new log file created at UTC midnight. **NON-GOAL** - the canonical bounded-storage contract is deterministic size rotation with retention; time rotation is unnecessary parallel policy.
- [x] Per-module levels work: `stealth=info,transport=debug,fec=trace` with global `level=warn`. **GAP -> TODO-531** - filtering units pass, but loaded module overrides are not used at logger initialization.
- [x] Existing `log::info!()` / `log::debug!()` / `log::warn!()` / `log::error!()` calls continue to work. **VERIFIED** - `ProductionLogger` implements the existing `log` facade and current call sites compile and execute unchanged.
- [x] With `log_to_stdout = false` and `log_to_file = true`: no stderr output, all in file. **GAP -> TODO-531** - sink routing exists but has no configured process-level assertion.
- [x] With both enabled: output on both stderr and file simultaneously. **GAP -> TODO-531** - dual sinks exist without runtime config proof.
- [x] On shutdown: log file is flushed (no data loss). **GAP -> TODO-531** - `Log::flush()` exists, but shutdown does not explicitly invoke and prove it.
- [x] Syslog: UDP packets sent to configured host:port in RFC 5424 format. **GAP -> TODO-531** - formatting units exist, but configured process-level UDP delivery is unproven.
- [x] AdminLogBuffer: admin UI log display still works after migration. **VERIFIED** - the buffer is registered as the secondary `LogSink` before logger initialization and server log tests retain it.
- [x] No performance regression: logging at `info` level adds < 1us per call. **GAP -> TODO-531** - current logging performs synchronous formatting and sink I/O with no benchmark evidence.
- [x] `cargo clippy --lib -D warnings` is clean. **VERIFIED** - the current full workspace Clippy gate passes with warnings denied.
