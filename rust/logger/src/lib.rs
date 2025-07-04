use env_logger::Env;
use log::LevelFilter;

/// Initialize global logger using `env_logger`.
///
/// Log level can be configured via the `RUST_LOG` environment variable.
/// If unset, `info` is used by default.
pub fn init() {
    let env = Env::default().default_filter_or("info");
    // Ignore errors if the logger was already initialized
    let _ = env_logger::Builder::from_env(env)
        .format_timestamp_secs()
        .format_module_path(false)
        .try_init();
}
