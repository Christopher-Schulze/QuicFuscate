//! Root compatibility surface for the standalone production logging crate.

pub use qf_logging::{
    flush, format_rfc5424, level_to_severity, reopen, rfc3339_utc, rfc3339_utc_checked, rotate,
    set_admin_sink, stats, FlushGuard, LogInitError, LogSink, LoggerStats, SizeRotatingAppender,
    SyslogWriter, DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_SIZE, DEFAULT_SYSLOG_FACILITY, LOG_FILE_MODE,
    LOG_QUEUE_CAPACITY,
};

#[cfg(feature = "rust-tests")]
pub use qf_logging::{format_json, format_text};

/// Projects an owner configuration into the standalone logger configuration.
pub trait LoggingConfigProjection {
    /// Return the standalone logger configuration for this owner configuration.
    fn project_logging_config(&self) -> qf_logging::LoggingConfig;
}

/// Initialize the standalone logger from an owner configuration.
pub fn init<C: LoggingConfigProjection>(config: &C) -> Result<(), LogInitError> {
    qf_logging::init(&config.project_logging_config())
}
