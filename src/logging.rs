//! Root compatibility surface for the standalone production logging crate.

pub use qf_logging::{
    flush, format_rfc5424, level_to_severity, reopen, rfc3339_utc, rfc3339_utc_checked, rotate,
    set_admin_sink, stats, FlushGuard, LogInitError, LogSink, LoggerStats, SizeRotatingAppender,
    SyslogWriter, DEFAULT_MAX_FILES, DEFAULT_MAX_FILE_SIZE, DEFAULT_SYSLOG_FACILITY, LOG_FILE_MODE,
    LOG_QUEUE_CAPACITY,
};

#[cfg(feature = "rust-tests")]
pub use qf_logging::{format_json, format_text};

/// Initialize the standalone logger from the engine-owned configuration.
pub fn init(config: &crate::engine::LoggingConfig) -> Result<(), LogInitError> {
    qf_logging::init(&project_config(config))
}

fn project_config(config: &crate::engine::LoggingConfig) -> qf_logging::LoggingConfig {
    qf_logging::LoggingConfig {
        mode: match config.mode {
            crate::engine::LoggingMode::Verbose => qf_logging::LoggingMode::Verbose,
            crate::engine::LoggingMode::Normal => qf_logging::LoggingMode::Normal,
            crate::engine::LoggingMode::Minimal => qf_logging::LoggingMode::Minimal,
            crate::engine::LoggingMode::NoLog => qf_logging::LoggingMode::NoLog,
        },
        level: config.level.clone(),
        log_to_file: config.log_to_file,
        log_file_path: config.log_file_path.clone(),
        log_to_stdout: config.log_to_stdout,
        ring_buffer_capacity: config.ring_buffer_capacity,
        strip_metadata: config.strip_metadata,
        format: match config.format {
            crate::engine::LogFormat::Text => qf_logging::LogFormat::Text,
            crate::engine::LogFormat::Json => qf_logging::LogFormat::Json,
            crate::engine::LogFormat::Syslog => qf_logging::LogFormat::Syslog,
        },
        file_path: config.file_path.clone(),
        max_file_size_bytes: config.max_file_size_bytes,
        max_files: config.max_files,
        syslog_addr: config.syslog_addr,
        module_levels: config.module_levels.clone(),
    }
}
