---
id: TODO-446
title: Production logging (structured JSON, file output, rotation, per-module levels)
severity: HIGH
phase: "I"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-446: Production Logging

## Problem

### No log rotation

There is no log rotation mechanism. Logs are written to a single file (or stderr)
that grows without bound. In production, this leads to disk exhaustion and makes
log analysis impractical. A production VPN server running 24/7 can generate
gigabytes of logs per week.

### No structured JSON logging

All logging uses the `log` crate's plain-text format (e.g., `log::info!("Kill
switch enabled")`). There is no structured JSON output. This makes log
aggregation (ELK, Loki, Datadog, Splunk) difficult — log parsers must use
regex or grok patterns instead of direct JSON ingestion.

### log_file_path is configured but not used

The `LoggingConfig` struct (`src/engine/config.rs:605-618`) has a `log_file_path`
field:

```rust
pub struct LoggingConfig {
    pub mode: LoggingMode,
    pub level: String,
    pub log_to_file: bool,
    pub log_file_path: String,       // line 611 — "configured" but not wired
    pub log_to_stdout: bool,
    pub ring_buffer_capacity: usize,
    pub strip_metadata: bool,
}
```

The default value is `"/var/log/quicfuscate.log"` (line 626), and the config
file `config/quicfuscate.toml:385` sets it:

```toml
log_file_path = "/var/log/quicfuscate.log"
```

But this path is never actually opened or written to. The `log_to_file` field
defaults to `false` (line 625), and even when set to `true`, there is no file
appender implementation. All log output goes to stderr only.

### No per-module log levels

The config has a single `level` field (`src/engine/config.rs:607`) that applies
to all modules. There is no way to set `stealth=info, transport=debug, fec=trace`
— different subsystems cannot have different verbosity levels. In production,
you want `info` globally but `debug` for a specific module being investigated.

### Current logging initialization

The `log` crate is used throughout the codebase (e.g., `killswitch.rs:46`
`log::info!("Kill switch enabled")`, `routing.rs:69` `log::info!(...)`). The
`tracing` crate is mentioned in comments (`src/main.rs:1426`) but is not used
for log output. There is no `tracing-subscriber` setup, no `EnvFilter`, no
file appender.

## Goal

1. **Structured JSON logging** — one JSON object per line (NDJSON), with
   `timestamp`, `level`, `target`, `message`, and structured `fields`.

2. **Log file output** — configurable file path, actually opened and written to.

3. **Log rotation** — size-based (rotate at N MB, keep N files) and time-based
   (rotate daily). Uses `tracing-appender`'s `RollingFileAppender` for
   time-based and a custom wrapper for size-based.

4. **Per-module log levels** — `stealth=info,transport=debug,fec=trace` via
   `EnvFilter` directive syntax.

5. **Dual output** — simultaneous file + stderr (configurable independently).

## Implementation Plan

### Step 1: Add tracing dependencies

Add to `Cargo.toml`:

```toml
[dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter", "fmt"] }
tracing-appender = "0.2"
```

The `tracing` crate is a superset of `log` — with the `tracing-log` adapter,
existing `log::info!()` calls are automatically forwarded to the tracing
subscriber. This means **no code changes needed** in the 100+ existing
`log::info!` / `log::debug!` / `log::warn!` / `log::error!` call sites.

### Step 2: Initialize tracing subscriber

Create a logging initialization module:

```rust
// src/logging.rs (new file)

use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use tracing_appender::rolling;
use std::path::PathBuf;

pub fn init(config: &LoggingConfig) -> Result<(), LogInitError> {
    // Build EnvFilter from config level + per-module directives
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            // Parse per-module directives from config
            // e.g., "info,stealth=debug,transport=trace,fec=trace"
            EnvFilter::new(&build_filter_string(config))
        });

    let registry = tracing_subscriber::registry().with(filter);

    // stderr layer (plain text or JSON, configurable)
    let stderr_layer = if config.log_to_stdout {
        if config.log_format == "json" {
            Some(fmt::layer()
                .json()
                .with_writer(std::io::stderr)
                .boxed())
        } else {
            Some(fmt::layer()
                .with_writer(std::io::stderr)
                .boxed())
        }
    } else {
        None
    };

    // File layer with rotation
    let file_layer = if config.log_to_file {
        let file_appender = create_file_appender(config)?;
        let file_writer = file_appender.make_writer();

        if config.log_format == "json" {
            Some(fmt::layer()
                .json()
                .with_writer(file_writer)
                .boxed())
        } else {
            Some(fmt::layer()
                .with_writer(file_writer)
                .boxed())
        }
    } else {
        None
    };

    registry
        .with(stderr_layer)
        .with(file_layer)
        .init();

    // Bridge existing `log` crate macros to tracing
    tracing_log::LogTracer::init()?;

    Ok(())
}

fn build_filter_string(config: &LoggingConfig) -> String {
    let mut parts = vec![config.level.clone()];
    for (module, level) in &config.module_levels {
        parts.push(format!("{}={}", module, level));
    }
    parts.join(",")
}

fn create_file_appender(config: &LoggingConfig) -> Result<RollingFileAppender, LogInitError> {
    let path = PathBuf::from(&config.log_file_path);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let prefix = path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("quicfuscate.log"));

    match config.log_rotation {
        LogRotation::Daily => {
            Ok(rolling::daily(dir, prefix))
        }
        LogRotation::Hourly => {
            Ok(rolling::hourly(dir, prefix))
        }
        LogRotation::Never => {
            Ok(rolling::never(dir, prefix))
        }
        LogRotation::SizeBased { max_size_mb, keep } => {
            // Custom size-based appender
            Ok(SizeRotatingAppender::new(dir, prefix, max_size_mb, keep))
        }
    }
}
```

### Step 3: Size-based rotation

`tracing-appender` provides time-based rotation (daily, hourly, never) but not
size-based. Implement a custom `MakeWriter` that rotates when the file exceeds
a size threshold:

```rust
// src/logging.rs

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::Mutex;

pub struct SizeRotatingAppender {
    dir: PathBuf,
    prefix: OsString,
    max_size_bytes: u64,
    keep: usize,
    current: Mutex<CurrentFile>,
}

struct CurrentFile {
    file: File,
    path: PathBuf,
    size: u64,
}

impl SizeRotatingAppender {
    pub fn new(dir: PathBuf, prefix: &OsStr, max_size_mb: u64, keep: usize) -> Self {
        let max_size_bytes = max_size_mb * 1024 * 1024;
        let path = dir.join(prefix);
        let file = OpenOptions::new()
            .create(true).append(true).open(&path)
            .expect("open log file");
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        Self {
            dir,
            prefix: prefix.to_os_string(),
            max_size_bytes,
            keep,
            current: Mutex::new(CurrentFile { file, path, size }),
        }
    }

    fn maybe_rotate(&self, current: &mut CurrentFile) {
        if current.size < self.max_size_bytes {
            return;
        }
        // Rotate: current.log → current.1.log → current.2.log → ...
        for i in (1..self.keep).rev() {
            let from = self.dir.join(format!("{}.{}", self.prefix.to_string_lossy(), i));
            let to = self.dir.join(format!("{}.{}", self.prefix.to_string_lossy(), i + 1));
            let _ = std::fs::rename(&from, &to);
        }
        let archive = self.dir.join(format!("{}.1", self.prefix.to_string_lossy()));
        let _ = std::fs::rename(&current.path, &archive);

        // Open new file
        current.file = OpenOptions::new()
            .create(true).append(true).open(&current.path)
            .expect("open new log file");
        current.size = 0;
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for &'a SizeRotatingAppender {
    type Writer = SizeWriter<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        SizeWriter { appender: self }
    }
}

pub struct SizeWriter<'a> {
    appender: &'a SizeRotatingAppender,
}

impl<'a> Write for SizeWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut current = self.appender.current.lock().unwrap();
        let n = current.file.write(buf)?;
        current.size += n as u64;
        self.appender.maybe_rotate(&mut current);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.appender.current.lock().unwrap().file.flush()
    }
}
```

### Step 4: Extend LoggingConfig

Add new fields to `LoggingConfig` in `src/engine/config.rs:605-618`:

```rust
pub struct LoggingConfig {
    pub mode: LoggingMode,
    pub level: String,
    pub log_to_file: bool,
    pub log_file_path: String,
    pub log_to_stdout: bool,
    pub ring_buffer_capacity: usize,
    pub strip_metadata: bool,
    // NEW fields:
    /// Log format: "json" or "text"
    pub log_format: LogFormat,
    /// Log rotation strategy
    pub log_rotation: LogRotation,
    /// Per-module log levels: e.g., {"stealth": "info", "transport": "debug"}
    pub module_levels: HashMap<String, String>,
}

pub enum LogFormat {
    Json,
    Text,
}

pub enum LogRotation {
    Daily,
    Hourly,
    Never,
    SizeBased { max_size_mb: u64, keep: usize },
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            log_format: LogFormat::Text,
            log_rotation: LogRotation::SizeBased {
                max_size_mb: 100,
                keep: 5,
            },
            module_levels: HashMap::new(),
        }
    }
}
```

### Step 5: Config file

Update `config/quicfuscate.toml`:

```toml
[logging]
mode = "normal"
level = "info"
log_to_file = true
log_file_path = "/var/log/quicfuscate/server.log"
log_to_stdout = true
log_format = "json"                    # "json" | "text"
log_rotation = "size"                  # "daily" | "hourly" | "size" | "never"
log_rotation_size_mb = 100             # only for "size"
log_rotation_keep = 5                  # only for "size"
strip_metadata = false

# Per-module log levels (overrides global level for specific modules)
[logging.module_levels]
stealth = "info"
transport = "debug"
fec = "trace"
```

### Step 6: JSON log format

The JSON output (one event per line) should look like:

```json
{"timestamp":"2026-06-30T12:00:00.123Z","level":"INFO","target":"quicfuscate::killswitch","fields":{"message":"Kill switch enabled","vpn_connected":false}}
{"timestamp":"2026-06-30T12:00:01.456Z","level":"DEBUG","target":"quicfuscate::routing","fields":{"message":"Routing configured","subnet":"10.8.0.0/24","wan":"eth0"}}
```

Fields:
- `timestamp`: ISO 8601 UTC with millisecond precision
- `level`: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`
- `target`: Rust module path (e.g., `quicfuscate::implementations::server::mod`)
- `fields.message`: The log message
- `fields.*`: Any structured key-value pairs from the log call

### Step 7: Call init() at startup

In `src/main.rs` (client) and `src/implementations/server/mod.rs` (server),
call `logging::init(&config.logging)` early in startup, before any other
subsystem initializes:

```rust
// src/main.rs — near the top of main()
quicfuscate::logging::init(&config.logging)
    .expect("failed to initialize logging");
log::info!("QuicFuscate client starting (version {})", env!("CARGO_PKG_VERSION"));
```

### Step 8: Graceful shutdown of logging

Ensure the file appender is flushed on shutdown. `tracing-appender` provides a
`WorkerGuard` that must be held for the lifetime of the application — when
dropped, it flushes the buffer. Store the guard in the main function and drop
it last:

```rust
let _guard = quicfuscate::logging::init(&config.logging)?;
// ... application runs ...
// _guard dropped here → flush
```

## Files to Modify/Create

- `Cargo.toml` — add `tracing`, `tracing-subscriber`, `tracing-appender`,
  `tracing-log` dependencies
- `src/logging.rs` (new) — `init()`, `SizeRotatingAppender`, `build_filter_string()`,
  `create_file_appender()`
- `src/engine/config.rs:605-632` — add `log_format`, `log_rotation`,
  `module_levels` fields to `LoggingConfig`; add `LogFormat` and `LogRotation`
  enums
- `src/main.rs` — call `logging::init()` at startup, hold `_guard`
- `src/implementations/server/mod.rs` — call `logging::init()` at server startup
- `config/quicfuscate.toml:385` — add `[logging]` section with new fields
- `config/server-linux.default.toml` — add `[logging]` section
- `docs/DOCUMENTATION.md` — document logging configuration, JSON format, rotation

## Acceptance Criteria

- With `log_format = "json"`: each log line is valid JSON parseable by
  `jq '.'` — one event per line (NDJSON)
- JSON log line contains: `timestamp` (ISO 8601 UTC), `level`, `target`,
  `fields.message`
- With `log_to_file = true`: log file is created at `log_file_path` and written to
- With `log_rotation = "size"` and `log_rotation_size_mb = 1`: after writing
  > 1 MB of logs, a new file is created and the old file is renamed to
  `<name>.1`
- With `log_rotation_keep = 3`: at most 3 rotated files exist (plus the current)
- With `log_rotation = "daily"`: a new log file is created at UTC midnight
- With per-module levels `stealth=info,transport=debug,fec=trace` and global
  `level=warn`: `stealth` module logs at info, `transport` at debug, `fec` at
  trace, all others at warn
- Existing `log::info!()`, `log::debug!()`, `log::warn!()`, `log::error!()`
  calls continue to work (bridged via `tracing-log`)
- With `log_to_stdout = false` and `log_to_file = true`: no output on stderr,
  all output in file
- With `log_to_stdout = true` and `log_to_file = true`: output on both stderr
  and file simultaneously
- On shutdown: log file is flushed (no data loss)
- `cargo clippy --lib -D warnings` is clean
- No performance regression: logging at `info` level adds < 1us per call
  (tracing is zero-cost when level is disabled)

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| Log init (subscriber + file open) | < 10ms | One-time at startup |
| JSON log write (info level) | < 5us | Serialization + file write (buffered) |
| Text log write (info level) | < 2us | Simpler format |
| Disabled log level (e.g., trace off) | ~0ns | Tracing is zero-cost when filtered |
| File rotation (size trigger) | < 5ms | File rename + new file open |
| File rotation (daily trigger) | < 5ms | File rename + new file open |
| Memory (buffer) | ~64KB | tracing-appender internal buffer |
| Disk per day (info level, 100 clients) | ~50-500MB | Depends on traffic volume |
