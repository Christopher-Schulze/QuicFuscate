//! Production logging: structured JSON, size-rotating file appender, and RFC 5424 syslog.
//!
//! This module replaces `env_logger` with a production-grade logger built on the
//! `log` crate facade. It supports three output formats (`Text`, `Json`, `Syslog`),
//! size-based log file rotation, optional RFC 5424 syslog forwarding over UDP, and
//! per-module level overrides.
//!
//! The logger is installed once via [`init`]. A secondary in-memory sink
//! ([`LogSink`]) can be registered with [`set_admin_sink`] so that the Admin UI
//! ring buffer keeps receiving entries regardless of the configured output format.

use crossbeam_channel::{Receiver, Sender, TrySendError};
use log::{Level, LevelFilter, Log, Metadata, Record};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use qf_common::time_source::{now_system, unix_epoch_duration, WallClockError};

/// Logging mode used to derive the effective logger output policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LoggingMode {
    /// Full debug logging with all metadata to disk and stdout.
    Verbose,
    /// Info-level default operation.
    #[default]
    Normal,
    /// Warn-level only with client metadata stripped.
    Minimal,
    /// Strict privacy mode with no external sinks.
    NoLog,
}

/// Logging output format for the production logger.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable text (default).
    #[default]
    Text,
    /// Structured NDJSON output.
    Json,
    /// RFC 5424 syslog output.
    Syslog,
}

/// Logger configuration projected from the engine configuration boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub mode: LoggingMode,
    pub level: String,
    pub log_to_file: bool,
    pub log_file_path: String,
    pub log_to_stdout: bool,
    pub ring_buffer_capacity: usize,
    pub strip_metadata: bool,
    pub format: LogFormat,
    pub file_path: Option<PathBuf>,
    pub max_file_size_bytes: u64,
    pub max_files: usize,
    pub syslog_addr: Option<SocketAddr>,
    pub module_levels: HashMap<String, String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            mode: LoggingMode::Normal,
            level: "info".to_string(),
            log_to_file: false,
            log_file_path: "/var/log/quicfuscate.log".to_string(),
            log_to_stdout: true,
            ring_buffer_capacity: 512,
            strip_metadata: false,
            format: LogFormat::Text,
            file_path: None,
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE,
            max_files: DEFAULT_MAX_FILES,
            syslog_addr: None,
            module_levels: HashMap::new(),
        }
    }
}

impl LoggingConfig {
    /// Returns the effective logger settings after applying mode overrides.
    pub fn effective(&self) -> Self {
        let mut config = self.clone();
        match config.mode {
            LoggingMode::Verbose => {
                config.level = "debug".to_string();
            }
            LoggingMode::Normal => {}
            LoggingMode::Minimal => {
                config.level = "warn".to_string();
                config.strip_metadata = true;
            }
            LoggingMode::NoLog => {
                config.level = "off".to_string();
                config.log_to_file = false;
                config.log_to_stdout = false;
                config.strip_metadata = true;
                config.file_path = None;
                config.syslog_addr = None;
            }
        }
        config
    }

    /// Validate the operator-facing logger bounds.
    pub fn validate(&self) -> Result<(), String> {
        const VALID_LEVELS: &[&str] = &["off", "error", "warn", "info", "debug", "trace"];
        if !VALID_LEVELS.contains(&self.level.trim().to_ascii_lowercase().as_str()) {
            return Err(format!(
                "Invalid logging.level: {}. Must be one of: {:?}",
                self.level, VALID_LEVELS
            ));
        }
        if self.ring_buffer_capacity == 0 {
            return Err("logging.ring_buffer_capacity must be greater than zero".to_string());
        }
        if self.log_to_file && self.file_path.is_none() && self.log_file_path.trim().is_empty() {
            return Err(
                "logging.log_file_path must not be empty when log_to_file is enabled".to_string()
            );
        }
        if self.file_path.as_ref().is_some_and(|path| path.as_os_str().is_empty()) {
            return Err("logging.file_path must not be empty".to_string());
        }
        if (self.log_to_file || self.file_path.is_some()) && self.max_file_size_bytes == 0 {
            return Err(
                "logging.max_file_size_bytes must be greater than zero when file logging is enabled"
                    .to_string(),
            );
        }
        if self.max_files > 1024 {
            return Err("logging.max_files must not exceed 1024".to_string());
        }
        if self.syslog_addr.is_some_and(|address| address.port() == 0) {
            return Err("logging.syslog_addr port must be greater than zero".to_string());
        }
        for (module, level) in &self.module_levels {
            if module.trim().is_empty() {
                return Err("logging.module_levels keys must not be empty".to_string());
            }
            if !VALID_LEVELS.contains(&level.trim().to_ascii_lowercase().as_str()) {
                return Err(format!("Invalid logging.module_levels value for {module}: {level}"));
            }
        }
        Ok(())
    }
}

/// Default maximum file size before rotation (100 MiB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
/// Default number of rotated files to retain.
pub const DEFAULT_MAX_FILES: usize = 5;
/// Default syslog facility (user-level, RFC 5424).
pub const DEFAULT_SYSLOG_FACILITY: u8 = 1;
/// Bounded producer-to-writer queue. Saturation drops the newest record.
pub const LOG_QUEUE_CAPACITY: usize = 8192;
/// POSIX mode for operational log files, including newly opened and reopened files.
pub const LOG_FILE_MODE: u32 = 0o640;
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors returned by [`init`].
#[derive(Debug)]
pub enum LogInitError {
    /// Failed to create or open the log file.
    FileCreateError(io::Error),
    /// Failed to bind the syslog UDP socket.
    SyslogError(io::Error),
    /// Failed to start the owned logging worker.
    WorkerSpawnError(io::Error),
    /// A different global logger already owns the `log` facade.
    LoggerAlreadyInstalled,
}

impl std::fmt::Display for LogInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogInitError::FileCreateError(e) => write!(f, "log file create error: {}", e),
            LogInitError::SyslogError(e) => write!(f, "syslog init error: {}", e),
            LogInitError::WorkerSpawnError(e) => write!(f, "logging worker spawn error: {}", e),
            LogInitError::LoggerAlreadyInstalled => {
                write!(f, "a different global logger is already installed")
            }
        }
    }
}

impl std::error::Error for LogInitError {}

/// A secondary in-memory sink that receives every log record in addition to the
/// configured outputs. Implemented by the Admin UI ring buffer.
pub trait LogSink: Send + Sync {
    /// Push a log entry (level + pre-formatted message).
    fn push(&self, level: Level, msg: &str);
}

static ADMIN_SINK: OnceLock<Arc<dyn LogSink>> = OnceLock::new();
static LOGGER_CONTROL: OnceLock<LoggerControl> = OnceLock::new();

/// Register a secondary [`LogSink`] (e.g. the Admin UI ring buffer).
///
/// Safe to call once; subsequent calls are ignored.
pub fn set_admin_sink(sink: Arc<dyn LogSink>) {
    let _ = ADMIN_SINK.set(sink);
}

/// Initialize the production logger from a [`LoggingConfig`].
///
/// Installs the single owned global `log` logger and sets the maximum level.
/// Repeating this function after a successful installation is idempotent.
pub fn init(config: &LoggingConfig) -> Result<(), LogInitError> {
    if LOGGER_CONTROL.get().is_some() {
        return Ok(());
    }
    let eff = config.effective();

    let level = parse_level(&eff.level);
    let format = eff.format;

    // Resolve the file path: prefer the explicit `file_path`, fall back to the
    // legacy `log_file_path` string when `log_to_file` is enabled.
    let file_path = resolve_file_path(&eff);

    let file = if let Some(p) = file_path {
        let appender = SizeRotatingAppender::new(&p, eff.max_file_size_bytes, eff.max_files)
            .map_err(LogInitError::FileCreateError)?;
        Some(appender)
    } else {
        None
    };

    let to_stderr = eff.log_to_stdout;

    let syslog = if let Some(addr) = eff.syslog_addr {
        let writer = SyslogWriter::new(addr, "quicfuscate").map_err(LogInitError::SyslogError)?;
        Some(writer)
    } else {
        None
    };

    let module_levels: HashMap<String, LevelFilter> = eff
        .module_levels
        .iter()
        .map(|(k, v): (&String, &String)| (k.clone(), parse_level(v)))
        .collect();

    // The global max level must be at least as permissive as the most verbose
    // module override, otherwise those records would be filtered before reaching
    // the logger.
    let max_level = module_levels.values().copied().max().unwrap_or(level).max(level);

    let dropped_records = Arc::new(AtomicU64::new(0));
    let sink_errors = Arc::new(AtomicU64::new(0));
    let (sender, receiver) = crossbeam_channel::bounded(LOG_QUEUE_CAPACITY);
    let worker_errors = sink_errors.clone();
    let worker = std::thread::Builder::new()
        .name("qf-log-writer".to_string())
        .spawn(move || {
            run_writer(
                receiver,
                WriterSinks {
                    file,
                    to_stderr,
                    syslog,
                    format,
                    hostname: detect_hostname(),
                    app_name: "quicfuscate".to_string(),
                    procid: std::process::id().to_string(),
                },
                &worker_errors,
            );
        })
        .map_err(LogInitError::WorkerSpawnError)?;

    let logger = ProductionLogger {
        level,
        module_levels,
        sender: sender.clone(),
        dropped_records: dropped_records.clone(),
    };

    match log::set_boxed_logger(Box::new(logger)) {
        Ok(()) => {
            let _ = LOGGER_CONTROL.set(LoggerControl { sender, dropped_records, sink_errors });
            log::set_max_level(max_level);
            Ok(())
        }
        Err(_) => {
            shutdown_and_join_worker(&sender, worker);
            Err(LogInitError::LoggerAlreadyInstalled)
        }
    }
}

/// Flush every owned sink and wait for the writer to acknowledge durability.
pub fn flush() -> io::Result<()> {
    let Some(control) = LOGGER_CONTROL.get() else {
        return Ok(());
    };
    control.flush()
}

/// Force the active file sink through the owned writer thread.
///
/// The acknowledgement is delivered only after every earlier queued record has
/// been written and the active file has been flushed and rotated. A logger
/// without a file sink cannot satisfy this request and returns `NotFound`.
pub fn rotate() -> io::Result<()> {
    let control = LOGGER_CONTROL.get().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "production logger is not initialized")
    })?;
    control.rotate()
}

/// Reopen the active file sink through the owned writer thread.
///
/// Reopen is the external logrotate contract: after a pathname rename or
/// copytruncate, SIGHUP closes the old handle, opens the current pathname, and
/// refreshes tracked size before acknowledging the request.
pub fn reopen() -> io::Result<()> {
    let control = LOGGER_CONTROL.get().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "production logger is not initialized")
    })?;
    control.reopen()
}

/// Current bounded-worker counters.
pub fn stats() -> LoggerStats {
    LOGGER_CONTROL.get().map_or(LoggerStats::default(), LoggerControl::stats)
}

/// Flushes the global production logger on every return path.
pub struct FlushGuard;

impl FlushGuard {
    /// Create a clean-shutdown flush guard after successful logger initialization.
    pub fn new() -> Self {
        Self
    }
}

impl Default for FlushGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FlushGuard {
    fn drop(&mut self) {
        let _ = flush();
    }
}

/// Observable bounded-worker outcomes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoggerStats {
    /// Records rejected because the bounded queue was full or disconnected.
    pub dropped_records: u64,
    /// File, stderr, or syslog write/flush failures observed by the worker.
    pub sink_errors: u64,
}

struct LoggerControl {
    sender: Sender<LogCommand>,
    dropped_records: Arc<AtomicU64>,
    sink_errors: Arc<AtomicU64>,
}

impl LoggerControl {
    fn request(
        &self,
        command: impl FnOnce(Sender<io::Result<()>>) -> LogCommand,
    ) -> io::Result<()> {
        let (ack_tx, ack_rx) = crossbeam_channel::bounded(1);
        self.sender
            .send_timeout(command(ack_tx), FLUSH_TIMEOUT)
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error.to_string()))?;
        ack_rx
            .recv_timeout(FLUSH_TIMEOUT)
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error.to_string()))?
    }

    fn flush(&self) -> io::Result<()> {
        self.request(LogCommand::Flush)
    }

    fn rotate(&self) -> io::Result<()> {
        self.request(LogCommand::Rotate)
    }

    fn reopen(&self) -> io::Result<()> {
        self.request(LogCommand::Reopen)
    }

    fn stats(&self) -> LoggerStats {
        LoggerStats {
            dropped_records: self.dropped_records.load(Ordering::Relaxed),
            sink_errors: self.sink_errors.load(Ordering::Relaxed),
        }
    }
}

/// Resolve the effective file path for the rotating appender.
fn resolve_file_path(config: &LoggingConfig) -> Option<PathBuf> {
    if let Some(p) = &config.file_path {
        return Some(p.clone());
    }
    if config.log_to_file && !config.log_file_path.is_empty() {
        return Some(PathBuf::from(&config.log_file_path));
    }
    None
}
/// Parse a level string into a `LevelFilter`. Unknown values default to `Info`.
fn parse_level(s: &str) -> LevelFilter {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => LevelFilter::Off,
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

// ============================================================================
// ProductionLogger
// ============================================================================

struct ProductionLogger {
    level: LevelFilter,
    module_levels: HashMap<String, LevelFilter>,
    sender: Sender<LogCommand>,
    dropped_records: Arc<AtomicU64>,
}

impl Log for ProductionLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let target = metadata.target();
        if let Some(f) = self.module_levels.get(target) {
            return metadata.level() <= *f;
        }
        // Check ancestor module prefixes (e.g. "quicfuscate::engine" overrides "quicfuscate").
        if let Some((_, f)) = self
            .module_levels
            .iter()
            .filter(|(k, _)| {
                target.starts_with(k.as_str()) && target.as_bytes().get(k.len()) == Some(&b':')
            })
            .max_by_key(|(k, _)| k.len())
        {
            return metadata.level() <= *f;
        }
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        // Module-level filtering (handles overrides more/less verbose than global).
        if !self.enabled(record.metadata()) {
            return;
        }

        let owned = OwnedRecord {
            level: record.level(),
            target: record.target().to_string(),
            message: record.args().to_string(),
            file: record.file().map(str::to_string),
            line: record.line(),
        };
        if let Err(error) = self.sender.try_send(LogCommand::Record(owned)) {
            if matches!(error, TrySendError::Full(_) | TrySendError::Disconnected(_)) {
                self.dropped_records.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn flush(&self) {
        let _ = flush();
    }
}

struct OwnedRecord {
    level: Level,
    target: String,
    message: String,
    file: Option<String>,
    line: Option<u32>,
}

enum LogCommand {
    Record(OwnedRecord),
    Flush(Sender<io::Result<()>>),
    Rotate(Sender<io::Result<()>>),
    Reopen(Sender<io::Result<()>>),
    Shutdown,
}

struct WriterSinks {
    file: Option<SizeRotatingAppender>,
    to_stderr: bool,
    syslog: Option<SyslogWriter>,
    format: LogFormat,
    hostname: String,
    app_name: String,
    procid: String,
}

impl WriterSinks {
    fn write_record(&mut self, record: &OwnedRecord) -> u64 {
        if let Some(sink) = ADMIN_SINK.get() {
            sink.push(record.level, &record.message);
        }

        if self.file.is_none() && !self.to_stderr && self.syslog.is_none() {
            return 0;
        }
        let line = match self.format {
            LogFormat::Json => format_owned_json(record),
            LogFormat::Text => format_owned_text(record),
            LogFormat::Syslog => format_rfc5424(
                &self.hostname,
                &self.app_name,
                &self.procid,
                record.level,
                &record.message,
            ),
        };
        let mut line_bytes = line.into_bytes();
        line_bytes.push(b'\n');
        let mut errors = 0u64;
        if let Some(app) = &mut self.file {
            if app.write_line(&line_bytes).is_err() {
                errors += 1;
            }
        }
        if self.to_stderr && io::stderr().write_all(&line_bytes).is_err() {
            errors += 1;
        }
        if let Some(syslog) = &mut self.syslog {
            if syslog.write_line(record.level, &record.message).is_err() {
                errors += 1;
            }
        }
        errors
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut first_error = None;
        if let Some(app) = &mut self.file {
            if let Err(error) = app.flush() {
                first_error = Some(error);
            }
        }
        if self.to_stderr {
            if let Err(error) = io::stderr().flush() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let Some(app) = &mut self.file else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no file log sink configured"));
        };
        app.rotate()
    }

    fn reopen(&mut self) -> io::Result<()> {
        let Some(app) = &mut self.file else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no file log sink configured"));
        };
        app.reopen()
    }
}

fn shutdown_and_join_worker(sender: &Sender<LogCommand>, worker: std::thread::JoinHandle<()>) {
    let _ = sender.send(LogCommand::Shutdown);
    let _ = worker.join();
}

fn run_writer(receiver: Receiver<LogCommand>, mut sinks: WriterSinks, sink_errors: &AtomicU64) {
    while let Ok(command) = receiver.recv() {
        match command {
            LogCommand::Record(record) => {
                let errors = sinks.write_record(&record);
                if errors > 0 {
                    sink_errors.fetch_add(errors, Ordering::Relaxed);
                }
            }
            LogCommand::Flush(ack) => {
                let result = sinks.flush();
                if result.is_err() {
                    sink_errors.fetch_add(1, Ordering::Relaxed);
                }
                let _ = ack.send(result);
            }
            LogCommand::Rotate(ack) => {
                let result = sinks.rotate();
                if result.is_err() {
                    sink_errors.fetch_add(1, Ordering::Relaxed);
                }
                let _ = ack.send(result);
            }
            LogCommand::Reopen(ack) => {
                let result = sinks.reopen();
                if result.is_err() {
                    sink_errors.fetch_add(1, Ordering::Relaxed);
                }
                let _ = ack.send(result);
            }
            LogCommand::Shutdown => break,
        }
    }
    if sinks.flush().is_err() {
        sink_errors.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// SizeRotatingAppender
// ============================================================================

/// A file appender that rotates the active log file when it exceeds `max_size`
/// bytes, keeping up to `max_files` rotated copies.
///
/// Rotation scheme: `app.log` -> `app.log.1` -> `app.log.2` -> ... -> `app.log.N`.
/// The oldest file (`app.log.N`) is deleted on each rotation.
pub struct SizeRotatingAppender {
    file: Option<File>,
    path: PathBuf,
    current_size: u64,
    max_size: u64,
    max_files: usize,
}

impl SizeRotatingAppender {
    /// Create a new appender at `path`. The file is opened in append mode and
    /// its current size is detected so rotation accounting is correct across
    /// restarts.
    pub fn new(path: impl AsRef<Path>, max_size: u64, max_files: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = open_log_file(&path, false)?;
        let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self { file: Some(file), path, current_size, max_size, max_files })
    }

    /// Append a single line (bytes) to the file, rotating first if needed.
    pub fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        if self.max_size > 0
            && self.current_size > 0
            && self.current_size.saturating_add(line.len() as u64) > self.max_size
        {
            self.rotate()?;
        }
        let f = self.ensure_open()?;
        f.write_all(line)?;
        self.current_size = self.current_size.saturating_add(line.len() as u64);
        Ok(())
    }

    /// Flush the underlying file.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = &mut self.file {
            f.flush()?;
        }
        Ok(())
    }

    /// Current tracked file size in bytes.
    pub fn current_size(&self) -> u64 {
        self.current_size
    }

    fn ensure_open(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            self.file = Some(open_log_file(&self.path, false)?);
        }
        self.file.as_mut().ok_or_else(|| io::Error::other("log file handle unavailable after open"))
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.flush()?;
        // Close the active handle so rename succeeds on all platforms.
        self.file = None;

        let max = self.max_files;
        if max == 0 {
            // No rotated files retained: truncate in place.
            self.file = Some(open_log_file(&self.path, true)?);
            self.current_size = 0;
            return Ok(());
        }

        // Remove the oldest rotated file (app.log.<max>).
        let oldest = rotated_path(&self.path, max);
        let _ = std::fs::remove_file(&oldest);

        // Shift app.log.<i> -> app.log.<i+1> for i in (max-1 down to 1).
        if max > 1 {
            for i in (1..max).rev() {
                let from = rotated_path(&self.path, i);
                if from.exists() {
                    let to = rotated_path(&self.path, i + 1);
                    std::fs::rename(&from, &to)?;
                }
            }
        }

        // Move the active file to app.log.1.
        let first = rotated_path(&self.path, 1);
        std::fs::rename(&self.path, &first)?;
        self.current_size = 0;
        Ok(())
    }

    fn reopen(&mut self) -> io::Result<()> {
        self.flush()?;
        self.file = None;
        let file = open_log_file(&self.path, false)?;
        let current_size = file.metadata()?.len();
        self.current_size = current_size;
        self.file = Some(file);
        Ok(())
    }
}

fn open_log_file(path: &Path, truncate: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    if truncate {
        options.write(true).truncate(true);
    } else {
        options.create(true).append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(LOG_FILE_MODE);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(LOG_FILE_MODE))?;
    }
    Ok(file)
}

/// Build the rotated path `base.<n>`.
fn rotated_path(base: &Path, n: usize) -> PathBuf {
    let mut os = base.as_os_str().to_owned();
    os.push(format!(".{}", n));
    PathBuf::from(os)
}

// ============================================================================
// SyslogWriter
// ============================================================================

/// Writes RFC 5424 formatted syslog messages over UDP.
pub struct SyslogWriter {
    sock: UdpSocket,
    hostname: String,
    app_name: String,
    procid: String,
    facility: u8,
}

impl SyslogWriter {
    /// Create a new syslog writer bound to a local ephemeral port, targeting
    /// `addr` (default `127.0.0.1:514`).
    pub fn new(addr: SocketAddr, app_name: &str) -> io::Result<Self> {
        let bind_address = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = UdpSocket::bind(bind_address)?;
        sock.connect(addr)?;
        Ok(Self {
            sock,
            hostname: detect_hostname(),
            app_name: app_name.to_string(),
            procid: std::process::id().to_string(),
            facility: DEFAULT_SYSLOG_FACILITY,
        })
    }

    /// Format and send a single syslog message.
    pub fn write_line(&mut self, level: Level, msg: &str) -> io::Result<()> {
        let line = format_rfc5424_facility(
            self.facility,
            &self.hostname,
            &self.app_name,
            &self.procid,
            level,
            msg,
        );
        self.sock.send(line.as_bytes())?;
        Ok(())
    }

    /// Override the syslog facility (default: 1 = user).
    pub fn with_facility(mut self, facility: u8) -> Self {
        self.facility = facility;
        self
    }
}

/// Map a `log::Level` to an RFC 5424 severity code.
pub fn level_to_severity(level: Level) -> u8 {
    match level {
        Level::Error => 3, // Error
        Level::Warn => 4,  // Warning
        Level::Info => 6,  // Informational
        Level::Debug => 7, // Debug
        Level::Trace => 7, // Debug (no trace severity in RFC 5424)
    }
}

/// Format an RFC 5424 syslog message:
/// `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`.
pub fn format_rfc5424(
    hostname: &str,
    app_name: &str,
    procid: &str,
    level: Level,
    msg: &str,
) -> String {
    format_rfc5424_facility(DEFAULT_SYSLOG_FACILITY, hostname, app_name, procid, level, msg)
}

fn format_rfc5424_facility(
    facility: u8,
    hostname: &str,
    app_name: &str,
    procid: &str,
    level: Level,
    msg: &str,
) -> String {
    let severity = level_to_severity(level);
    let pri = (facility as u32) * 8 + severity as u32;
    let ts = rfc3339_utc(now_system());
    format!("<{}>1 {} {} {} {} - - {}", pri, ts, hostname, app_name, procid, msg)
}

// ============================================================================
// Formatting helpers
// ============================================================================

/// Format a record as a human-readable text line (no trailing newline).
#[cfg(any(test, feature = "rust-tests"))]
pub fn format_text(record: &Record) -> String {
    let ts = rfc3339_utc(now_system());
    format!("{} [{}] {}: {}", ts, record.level(), record.target(), record.args())
}

/// Format a record as a single NDJSON line (no trailing newline).
#[cfg(any(test, feature = "rust-tests"))]
pub fn format_json(record: &Record) -> String {
    let ts = rfc3339_utc(now_system());
    let mut obj = serde_json::Map::new();
    obj.insert("ts".into(), serde_json::Value::String(ts));
    obj.insert("level".into(), serde_json::Value::String(record.level().as_str().to_lowercase()));
    obj.insert("target".into(), serde_json::Value::String(record.target().to_string()));
    obj.insert("msg".into(), serde_json::Value::String(record.args().to_string()));
    if let Some(file) = record.file() {
        obj.insert("file".into(), serde_json::Value::String(file.to_string()));
    }
    if let Some(line) = record.line() {
        obj.insert("line".into(), serde_json::Value::Number(serde_json::Number::from(line)));
    }
    serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
}

fn format_owned_text(record: &OwnedRecord) -> String {
    let ts = rfc3339_utc(now_system());
    format!("{} [{}] {}: {}", ts, record.level, record.target, record.message)
}

fn format_owned_json(record: &OwnedRecord) -> String {
    let ts = rfc3339_utc(now_system());
    let mut obj = serde_json::Map::new();
    obj.insert("ts".into(), serde_json::Value::String(ts));
    obj.insert("level".into(), serde_json::Value::String(record.level.as_str().to_lowercase()));
    obj.insert("target".into(), serde_json::Value::String(record.target.clone()));
    obj.insert("msg".into(), serde_json::Value::String(record.message.clone()));
    if let Some(file) = &record.file {
        obj.insert("file".into(), serde_json::Value::String(file.clone()));
    }
    if let Some(line) = record.line {
        obj.insert("line".into(), serde_json::Value::Number(serde_json::Number::from(line)));
    }
    serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
}

/// Format `SystemTime` as an RFC 3339 UTC timestamp with millisecond precision.
pub fn rfc3339_utc(now: SystemTime) -> String {
    rfc3339_utc_checked(now).unwrap_or_else(|_| "INVALID-TIMESTAMP".to_string())
}

/// Format `SystemTime` as RFC 3339, returning the wall-clock conversion error.
pub fn rfc3339_utc_checked(now: SystemTime) -> Result<String, WallClockError> {
    let dur = unix_epoch_duration(now)?;
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(days);
    Ok(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, mo, d, h, m, s, millis))
}

/// Convert days since the Unix epoch (1970-01-01) to a proleptic Gregorian date.
/// Based on Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Best-effort hostname detection (no extra dependency).
fn detect_hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    "localhost".to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;
    use std::fs;
    use std::path::PathBuf;
    use std::time::UNIX_EPOCH;

    fn build_and_format<F>(level: Level, target: &str, msg: &str, formatter: F) -> String
    where
        F: Fn(&Record) -> String,
    {
        let args = format_args!("{}", msg);
        let r = Record::builder().level(level).target(target).args(args).build();
        formatter(&r)
    }

    #[test]
    fn json_format_contains_required_fields() {
        let line = build_and_format(Level::Info, "quicfuscate::engine", "hello world", format_json);
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        let obj = v.as_object().expect("JSON object");
        assert_eq!(obj.get("level").and_then(|x| x.as_str()), Some("info"));
        assert_eq!(obj.get("target").and_then(|x| x.as_str()), Some("quicfuscate::engine"));
        assert_eq!(obj.get("msg").and_then(|x| x.as_str()), Some("hello world"));
        assert!(obj.get("ts").and_then(|x| x.as_str()).is_some());
    }

    #[test]
    fn text_format_is_human_readable() {
        let line = build_and_format(Level::Warn, "net", "dropped packet", format_text);
        assert!(line.contains("[WARN]"));
        assert!(line.contains("net"));
        assert!(line.contains("dropped packet"));
        // RFC 3339 timestamp contains 'T' separator and 'Z' suffix.
        assert!(line.contains('T'));
        assert!(line.contains('Z'));
    }

    fn unique_log_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_nanos();
        std::env::temp_dir().join(format!("qf-log-{label}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn syslog_format_follows_rfc5424() {
        let line = format_rfc5424("host01", "quicfuscate", "4242", Level::Error, "boom");
        // <PRI>VERSION ...
        assert!(line.starts_with('<'));
        // PRI for facility=1, severity=3 (Error) = 11.
        assert!(line.starts_with("<11>1 "));
        // Timestamp, hostname, app-name, procid, msgid(-), structured-data(-), msg.
        let parts: Vec<&str> = line.splitn(8, ' ').collect();
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0], "<11>1");
        assert!(parts[1].ends_with('Z'));
        assert_eq!(parts[2], "host01");
        assert_eq!(parts[3], "quicfuscate");
        assert_eq!(parts[4], "4242");
        assert_eq!(parts[5], "-"); // MSGID
        assert_eq!(parts[6], "-"); // STRUCTURED-DATA
        assert_eq!(parts[7], "boom");
    }

    #[test]
    fn level_to_severity_mapping() {
        assert_eq!(level_to_severity(Level::Error), 3);
        assert_eq!(level_to_severity(Level::Warn), 4);
        assert_eq!(level_to_severity(Level::Info), 6);
        assert_eq!(level_to_severity(Level::Debug), 7);
        assert_eq!(level_to_severity(Level::Trace), 7);
    }

    #[test]
    fn configuration_enums_preserve_engine_wire_names() {
        assert_eq!(serde_json::to_string(&LoggingMode::NoLog).unwrap(), "\"no-log\"");
        assert_eq!(serde_json::to_string(&LogFormat::Syslog).unwrap(), "\"syslog\"");
        assert_eq!(
            serde_json::from_str::<LoggingMode>("\"minimal\"").unwrap(),
            LoggingMode::Minimal
        );
        assert_eq!(serde_json::from_str::<LogFormat>("\"json\"").unwrap(), LogFormat::Json);
    }

    #[test]
    fn logging_config_preserves_wire_shape_and_validation() {
        let config = LoggingConfig::default();
        assert!(config.validate().is_ok());

        let encoded = serde_json::to_string(&config).expect("logging config serializes");
        let decoded: LoggingConfig = serde_json::from_str(&encoded).expect("logging config parses");
        assert_eq!(decoded, config);

        let mut invalid = config;
        invalid.ring_buffer_capacity = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rfc3339_is_valid_format() {
        let ts = rfc3339_utc(SystemTime::now());
        // YYYY-MM-DDTHH:MM:SS.mmmZ
        assert_eq!(ts.len(), 24);
        assert_eq!(ts.chars().nth(4), Some('-'));
        assert_eq!(ts.chars().nth(10), Some('T'));
        assert_eq!(ts.chars().nth(19), Some('.'));
        assert_eq!(ts.chars().nth(23), Some('Z'));
    }

    #[test]
    fn rfc3339_rejects_pre_epoch_without_epoch_zero() {
        let before_epoch = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(rfc3339_utc_checked(before_epoch), Err(WallClockError::BeforeUnixEpoch));
        assert_eq!(rfc3339_utc(before_epoch), "INVALID-TIMESTAMP");
    }

    #[test]
    fn size_rotation_creates_numbered_files() {
        let dir = std::env::temp_dir().join(format!("qf_log_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");

        // max_size = 12 bytes, keep 3 rotated files.
        let mut app = SizeRotatingAppender::new(&path, 12, 3).unwrap();
        // Each line is 6 bytes ("hello\n"). After 2 lines (12 bytes) the 3rd triggers rotation.
        app.write_line(b"hello\n").unwrap();
        app.write_line(b"hello\n").unwrap();
        app.write_line(b"hello\n").unwrap();
        app.flush().unwrap();
        drop(app);

        // After rotation: app.log (current) + app.log.1 (previous active).
        assert!(path.exists(), "active log exists");
        let one = rotated_path(&path, 1);
        assert!(one.exists(), "app.log.1 exists after first rotation");
        // Contents of app.log.1 should be the pre-rotation active file (2 lines).
        let one_content = fs::read_to_string(&one).unwrap();
        assert_eq!(one_content, "hello\nhello\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn size_rotation_shifts_oldest_out() {
        let dir = std::env::temp_dir().join(format!("qf_log_rot_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");

        // max_size = 6 bytes (one "hello\n" line), keep 2 rotated files.
        let mut app = SizeRotatingAppender::new(&path, 6, 2).unwrap();
        for _ in 0..5 {
            app.write_line(b"hello\n").unwrap();
        }
        app.flush().unwrap();
        drop(app);

        // With max_files=2, only app.log.1 and app.log.2 are retained.
        assert!(path.exists());
        assert!(rotated_path(&path, 1).exists());
        assert!(rotated_path(&path, 2).exists());
        assert!(!rotated_path(&path, 3).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn reopen_rebinds_after_external_rename() {
        let dir = unique_log_dir("rename");
        fs::create_dir_all(&dir).expect("create log test directory");
        let path = dir.join("app.log");
        let renamed = dir.join("app.log.20260805");

        let mut app = SizeRotatingAppender::new(&path, 1024, 2).expect("create appender");
        app.write_line(b"before\n").expect("write before rename");
        app.flush().expect("flush before rename");
        fs::rename(&path, &renamed).expect("external rename");

        app.reopen().expect("reopen renamed sink");
        app.write_line(b"after\n").expect("write after reopen");
        app.flush().expect("flush after reopen");

        assert_eq!(fs::read_to_string(&renamed).expect("read renamed file"), "before\n");
        assert_eq!(fs::read_to_string(&path).expect("read reopened active file"), "after\n");
        assert_eq!(app.current_size(), 6);
        fs::remove_dir_all(&dir).expect("remove log test directory");
    }

    #[test]
    fn reopen_refreshes_size_after_external_copytruncate() {
        let dir = unique_log_dir("copytruncate");
        fs::create_dir_all(&dir).expect("create log test directory");
        let path = dir.join("app.log");

        let mut app = SizeRotatingAppender::new(&path, 1024, 2).expect("create appender");
        app.write_line(b"before\n").expect("write before copytruncate");
        app.flush().expect("flush before copytruncate");
        OpenOptions::new().write(true).truncate(true).open(&path).expect("truncate active file");

        app.reopen().expect("reopen truncated sink");
        assert_eq!(app.current_size(), 0);
        app.write_line(b"after\n").expect("write after reopen");
        app.flush().expect("flush after reopen");

        assert_eq!(fs::read_to_string(&path).expect("read active file"), "after\n");
        assert_eq!(app.current_size(), 6);
        fs::remove_dir_all(&dir).expect("remove log test directory");
    }

    #[test]
    fn writer_rotate_ack_follows_queued_record_and_flushes_before_rename() {
        let dir = unique_log_dir("writer-rotate");
        fs::create_dir_all(&dir).expect("create log test directory");
        let path = dir.join("app.log");
        let app = SizeRotatingAppender::new(&path, 1024, 2).expect("create appender");
        let sinks = WriterSinks {
            file: Some(app),
            to_stderr: false,
            syslog: None,
            format: LogFormat::Text,
            hostname: "localhost".to_string(),
            app_name: "quicfuscate".to_string(),
            procid: "test".to_string(),
        };
        let (sender, receiver) = crossbeam_channel::bounded(8);
        let sink_errors = Arc::new(AtomicU64::new(0));
        let worker_errors = Arc::clone(&sink_errors);
        let worker = std::thread::spawn(move || run_writer(receiver, sinks, &worker_errors));

        sender
            .send(LogCommand::Record(OwnedRecord {
                level: Level::Info,
                target: "test".to_string(),
                message: "before-rotate".to_string(),
                file: None,
                line: None,
            }))
            .expect("send record before rotation");
        let (rotate_tx, rotate_rx) = crossbeam_channel::bounded(1);
        sender.send(LogCommand::Rotate(rotate_tx)).expect("send rotation command");
        assert!(rotate_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("receive rotation acknowledgement")
            .is_ok());

        sender
            .send(LogCommand::Record(OwnedRecord {
                level: Level::Info,
                target: "test".to_string(),
                message: "after-rotate".to_string(),
                file: None,
                line: None,
            }))
            .expect("send record after rotation");
        let (flush_tx, flush_rx) = crossbeam_channel::bounded(1);
        sender.send(LogCommand::Flush(flush_tx)).expect("send flush command");
        assert!(flush_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("receive flush acknowledgement")
            .is_ok());
        sender.send(LogCommand::Shutdown).expect("send shutdown command");
        worker.join().expect("join logging worker");

        assert_eq!(sink_errors.load(Ordering::Relaxed), 0);
        assert!(fs::read_to_string(rotated_path(&path, 1))
            .expect("read rotated file")
            .contains("before-rotate"));
        assert!(fs::read_to_string(&path).expect("read active file").contains("after-rotate"));
        fs::remove_dir_all(&dir).expect("remove log test directory");
    }

    #[cfg(unix)]
    #[test]
    fn writer_reopen_ack_rebinds_after_external_rename() {
        let dir = unique_log_dir("writer-reopen");
        fs::create_dir_all(&dir).expect("create log test directory");
        let path = dir.join("app.log");
        let renamed = dir.join("app.log.20260805");
        let app = SizeRotatingAppender::new(&path, 1024, 2).expect("create appender");
        let sinks = WriterSinks {
            file: Some(app),
            to_stderr: false,
            syslog: None,
            format: LogFormat::Text,
            hostname: "localhost".to_string(),
            app_name: "quicfuscate".to_string(),
            procid: "test".to_string(),
        };
        let (sender, receiver) = crossbeam_channel::bounded(8);
        let sink_errors = Arc::new(AtomicU64::new(0));
        let worker_errors = Arc::clone(&sink_errors);
        let worker = std::thread::spawn(move || run_writer(receiver, sinks, &worker_errors));

        sender
            .send(LogCommand::Record(OwnedRecord {
                level: Level::Info,
                target: "test".to_string(),
                message: "before-reopen".to_string(),
                file: None,
                line: None,
            }))
            .expect("send record before reopen");
        let (flush_tx, flush_rx) = crossbeam_channel::bounded(1);
        sender.send(LogCommand::Flush(flush_tx)).expect("send pre-reopen flush");
        assert!(flush_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("receive pre-reopen flush acknowledgement")
            .is_ok());
        fs::rename(&path, &renamed).expect("external rename");

        let (reopen_tx, reopen_rx) = crossbeam_channel::bounded(1);
        sender.send(LogCommand::Reopen(reopen_tx)).expect("send reopen command");
        assert!(reopen_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("receive reopen acknowledgement")
            .is_ok());
        sender
            .send(LogCommand::Record(OwnedRecord {
                level: Level::Info,
                target: "test".to_string(),
                message: "after-reopen".to_string(),
                file: None,
                line: None,
            }))
            .expect("send record after reopen");
        let (post_flush_tx, post_flush_rx) = crossbeam_channel::bounded(1);
        sender.send(LogCommand::Flush(post_flush_tx)).expect("send post-reopen flush");
        assert!(post_flush_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("receive post-reopen flush acknowledgement")
            .is_ok());
        sender.send(LogCommand::Shutdown).expect("send shutdown command");
        worker.join().expect("join logging worker");

        assert_eq!(sink_errors.load(Ordering::Relaxed), 0);
        assert!(fs::read_to_string(&renamed).expect("read renamed file").contains("before-reopen"));
        assert!(fs::read_to_string(&path)
            .expect("read reopened active file")
            .contains("after-reopen"));
        fs::remove_dir_all(&dir).expect("remove log test directory");
    }

    #[cfg(unix)]
    #[test]
    fn size_rotating_appender_reasserts_mode_across_create_reopen_and_rotation() {
        use std::os::unix::fs::PermissionsExt;

        let _umask = test_support::permissive_umask();
        let dir = std::env::temp_dir().join(format!("qf_log_mode_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");
        let mode = || fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        let app = SizeRotatingAppender::new(&path, 6, 2).unwrap();
        assert_eq!(mode(), LOG_FILE_MODE);

        drop(app);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut app = SizeRotatingAppender::new(&path, 6, 2).unwrap();
        assert_eq!(mode(), LOG_FILE_MODE);

        app.file = None;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        app.write_line(b"hello\n").unwrap();
        assert_eq!(mode(), LOG_FILE_MODE);
        app.write_line(b"hello\n").unwrap();
        app.flush().unwrap();

        assert_eq!(mode(), LOG_FILE_MODE);
        assert_eq!(
            fs::metadata(rotated_path(&path, 1)).unwrap().permissions().mode() & 0o777,
            LOG_FILE_MODE
        );
        drop(app);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_level_maps_known_strings() {
        assert_eq!(parse_level("error"), LevelFilter::Error);
        assert_eq!(parse_level("WARN"), LevelFilter::Warn);
        assert_eq!(parse_level("Info"), LevelFilter::Info);
        assert_eq!(parse_level("debug"), LevelFilter::Debug);
        assert_eq!(parse_level("trace"), LevelFilter::Trace);
        assert_eq!(parse_level("off"), LevelFilter::Off);
        // Unknown defaults to Info.
        assert_eq!(parse_level("nope"), LevelFilter::Info);
    }

    #[test]
    fn logger_enabled_respects_module_overrides() {
        let mut module_levels = HashMap::new();
        module_levels.insert("quicfuscate::net".to_string(), LevelFilter::Debug);
        let (sender, _receiver) = crossbeam_channel::bounded(1);
        let logger = ProductionLogger {
            level: LevelFilter::Warn,
            module_levels,
            sender,
            dropped_records: Arc::new(AtomicU64::new(0)),
        };

        // Global level is Warn: Info from unknown module is filtered.
        let m = Metadata::builder().level(Level::Info).target("other").build();
        assert!(!logger.enabled(&m));

        // Module override allows Debug from "quicfuscate::net".
        let m2 = Metadata::builder().level(Level::Debug).target("quicfuscate::net").build();
        assert!(logger.enabled(&m2));

        // Ancestor prefix override: "quicfuscate::net::tcp" inherits "quicfuscate::net".
        let m3 = Metadata::builder().level(Level::Debug).target("quicfuscate::net::tcp").build();
        assert!(logger.enabled(&m3));

        // Trace is above the module override (Debug), filtered.
        let m4 = Metadata::builder().level(Level::Trace).target("quicfuscate::net").build();
        assert!(!logger.enabled(&m4));
    }

    #[test]
    fn resolve_file_path_prefers_explicit_path() {
        let cfg = LoggingConfig {
            file_path: Some(PathBuf::from("/tmp/explicit.log")),
            log_to_file: true,
            log_file_path: "/tmp/legacy.log".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_file_path(&cfg), Some(PathBuf::from("/tmp/explicit.log")));
    }

    #[test]
    fn resolve_file_path_falls_back_to_legacy() {
        let cfg = LoggingConfig {
            file_path: None,
            log_to_file: true,
            log_file_path: "/tmp/legacy.log".to_string(),
            ..Default::default()
        };
        assert_eq!(resolve_file_path(&cfg), Some(PathBuf::from("/tmp/legacy.log")));
    }

    #[test]
    fn resolve_file_path_none_when_disabled() {
        let cfg = LoggingConfig { file_path: None, log_to_file: false, ..Default::default() };
        assert_eq!(resolve_file_path(&cfg), None);
    }

    struct PreinstalledLogger;

    impl Log for PreinstalledLogger {
        fn enabled(&self, _metadata: &Metadata) -> bool {
            false
        }

        fn log(&self, _record: &Record) {}

        fn flush(&self) {}
    }

    static PREINSTALLED_LOGGER: PreinstalledLogger = PreinstalledLogger;

    #[test]
    fn failed_installation_joins_worker_before_returning() {
        assert!(LOGGER_CONTROL.get().is_none(), "logger control must be uninitialized");
        let _ = log::set_logger(&PREINSTALLED_LOGGER);

        let directory = unique_log_dir("failed-installation");
        fs::create_dir_all(&directory).expect("create failed-installation directory");
        let path = directory.join("app.log");
        let config = LoggingConfig {
            log_to_stdout: false,
            file_path: Some(path.clone()),
            max_file_size_bytes: 1024,
            max_files: 1,
            ..Default::default()
        };

        assert!(matches!(init(&config), Err(LogInitError::LoggerAlreadyInstalled)));
        assert!(path.exists(), "failed initialization should create its configured sink");
        fs::remove_file(&path).expect("failed initialization must release its file sink");
        fs::remove_dir_all(&directory).expect("remove failed-installation directory");
    }

    #[test]
    fn shutdown_and_join_waits_for_worker_completion() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let (shutdown_seen_tx, shutdown_seen_rx) = crossbeam_channel::bounded(1);
        let (release_tx, release_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            assert!(matches!(receiver.recv(), Ok(LogCommand::Shutdown)));
            shutdown_seen_tx.send(()).expect("report shutdown receipt");
            release_rx.recv().expect("wait for join assertion");
        });

        let (cleanup_done_tx, cleanup_done_rx) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            shutdown_and_join_worker(&sender, worker);
            cleanup_done_tx.send(()).expect("report joined worker");
        });

        shutdown_seen_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker must receive shutdown before cleanup returns");
        assert!(cleanup_done_rx.try_recv().is_err(), "cleanup returned before worker exit");
        release_tx.send(()).expect("release worker for join");
        cleanup_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cleanup must return after joining worker");
    }

    #[cfg(unix)]
    mod test_support {
        use std::sync::{Mutex, MutexGuard, OnceLock};

        static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

        pub(super) struct UmaskGuard {
            previous: libc::mode_t,
            _lock: MutexGuard<'static, ()>,
        }

        pub(super) fn permissive_umask() -> UmaskGuard {
            let lock = UMASK_LOCK.get_or_init(|| Mutex::new(()));
            let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = unsafe { libc::umask(0) };
            UmaskGuard { previous, _lock: guard }
        }

        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::umask(self.previous);
                }
            }
        }
    }
}
