//! Tokio runtime management for the client.

use std::future::Future;
use std::sync::Arc;
use tokio::runtime::{Builder, Handle, Runtime};

/// Runtime configuration for the client.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Number of worker threads (0 = auto)
    pub worker_threads: usize,
    /// Thread name prefix
    pub thread_name: String,
    /// Enable I/O driver
    pub enable_io: bool,
    /// Enable time driver
    pub enable_time: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: 0,
            thread_name: "qf-client".to_string(),
            enable_io: true,
            enable_time: true,
        }
    }
}

/// Creates a tokio runtime with the given configuration.
pub fn create_runtime(config: &RuntimeConfig) -> std::io::Result<Runtime> {
    let mut builder = if config.worker_threads == 1 {
        Builder::new_current_thread()
    } else {
        let mut mt = Builder::new_multi_thread();
        if config.worker_threads > 0 {
            mt.worker_threads(config.worker_threads);
        }
        mt
    };

    builder.thread_name(&config.thread_name);

    if config.enable_io {
        builder.enable_io();
    }
    if config.enable_time {
        builder.enable_time();
    }

    builder.build()
}

/// Shared runtime handle for async operations.
pub type SharedRuntime = Arc<Runtime>;

/// Create a shared runtime.
pub fn create_shared_runtime(config: &RuntimeConfig) -> std::io::Result<SharedRuntime> {
    Ok(Arc::new(create_runtime(config)?))
}

/// Drive a client-owned future from a synchronous API without nesting Tokio runtimes.
///
/// The application runtime is multi-threaded, so `block_in_place` temporarily hands its worker
/// back to Tokio before driving the client-owned runtime. Calls made outside any Tokio runtime can
/// block the client runtime directly.
pub(crate) fn block_on<F>(runtime: &SharedRuntime, future: F) -> F::Output
where
    F: Future,
{
    if Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| runtime.block_on(future))
    } else {
        runtime.block_on(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_runtime_default() {
        let config = RuntimeConfig::default();
        let runtime = create_runtime(&config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_create_runtime_single_thread() {
        let config = RuntimeConfig { worker_threads: 1, ..Default::default() };
        let runtime = create_runtime(&config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn block_on_from_outer_runtime_does_not_nest() {
        let client_runtime =
            create_shared_runtime(&RuntimeConfig::default()).expect("client runtime");
        let outer_runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("outer runtime");

        let value = outer_runtime.block_on(async { block_on(&client_runtime, async { 42 }) });
        assert_eq!(value, 42);
    }
}
