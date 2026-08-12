use super::*;

pub struct MetricsServer {
    pub(super) addr: std::net::SocketAddr,
    pub(super) metrics: Arc<Metrics>,
    pub(super) shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl MetricsServer {
    /// Create a new metrics server.
    pub fn new(port: u16, metrics: Arc<Metrics>) -> Self {
        Self {
            addr: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            metrics,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub(super) async fn run_listener(&self, listener: TcpListener) -> std::io::Result<()> {
        let connection_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((socket, _addr))) => {
                    let permit = match connection_slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => continue,
                    };
                    let metrics = Arc::clone(&self.metrics);
                    tokio::spawn(async move {
                        handle_metrics_connection(socket, metrics).await;
                        drop(permit);
                    });
                }
                Ok(Err(e)) => {
                    log::warn!("Metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        Ok(())
    }

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Metrics server listening on http://{}", self.addr);

        let result = self.run_listener(listener).await;
        log::info!("Metrics server stopped");
        result
    }
}

/// Metrics HTTP server using global instrumentation.
///
/// This server reads from the global metrics registry at `crate::instrumentation::global()`.
#[cfg(any(test, feature = "rust-tests"))]
pub struct GlobalMetricsServer {
    pub(super) addr: std::net::SocketAddr,
    pub(super) shutdown: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(any(test, feature = "rust-tests"))]
impl GlobalMetricsServer {
    /// Create a new global metrics server.
    pub fn new(port: u16) -> Self {
        Self {
            addr: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub(super) async fn run_listener(&self, listener: TcpListener) -> std::io::Result<()> {
        let connection_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((socket, _addr))) => {
                    let permit = match connection_slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        handle_global_metrics_connection(socket).await;
                        drop(permit);
                    });
                }
                Ok(Err(e)) => {
                    log::warn!("Global metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        Ok(())
    }

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Global metrics server listening on http://{}", self.addr);

        let result = self.run_listener(listener).await;
        log::info!("Global metrics server stopped");
        result
    }
}
