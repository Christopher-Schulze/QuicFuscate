use super::super::http::{read_request, RequestReadError, MAX_CONCURRENT_CONNECTIONS};
use super::Metrics;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

fn parse_request_line(request: &[u8]) -> Option<(&str, &str)> {
    let line = request.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    Some((parts.next()?, parts.next()?))
}

fn route_path(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn bad_request_response() -> String {
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

fn too_large_response() -> String {
    "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

fn not_found_response() -> String {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

fn metrics_body_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )
}

fn health_body_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )
}

fn metrics_response(request: &[u8], metrics: &Metrics) -> String {
    let Some((method, path)) = parse_request_line(request) else {
        return bad_request_response();
    };

    match (method, route_path(path)) {
        ("GET", "/metrics") => metrics_body_response(&metrics.export()),
        ("GET", "/health") => health_body_response(&metrics.export_health()),
        _ => not_found_response(),
    }
}

#[cfg(any(test, feature = "rust-tests"))]
fn global_metrics_response(request: &[u8]) -> String {
    let Some((method, path)) = parse_request_line(request) else {
        return bad_request_response();
    };
    let global = crate::instrumentation::global();

    match (method, route_path(path)) {
        ("GET", "/metrics") => metrics_body_response(&global.export_prometheus()),
        ("GET", "/health") => health_body_response(&global.export_health()),
        _ => not_found_response(),
    }
}

async fn handle_metrics_connection(mut socket: TcpStream, metrics: Arc<Metrics>) {
    let response = match read_request(&mut socket).await {
        Ok(Some(request)) => metrics_response(&request, &metrics),
        Ok(None) => return,
        Err(RequestReadError::Incomplete) => bad_request_response(),
        Err(RequestReadError::TooLarge) => too_large_response(),
        Err(RequestReadError::TimedOut) => {
            log::debug!("Metrics server request read timed out");
            return;
        }
        Err(RequestReadError::Io(error)) => {
            log::debug!("Metrics server request read failed: {}", error);
            return;
        }
    };

    if let Err(error) = socket.write_all(response.as_bytes()).await {
        log::debug!("Metrics response write failed: {}", error);
    }
    if let Err(error) = socket.shutdown().await {
        log::debug!("Metrics socket shutdown failed: {}", error);
    }
}

#[cfg(any(test, feature = "rust-tests"))]
async fn handle_global_metrics_connection(mut socket: TcpStream) {
    let response = match read_request(&mut socket).await {
        Ok(Some(request)) => global_metrics_response(&request),
        Ok(None) => return,
        Err(RequestReadError::Incomplete) => bad_request_response(),
        Err(RequestReadError::TooLarge) => too_large_response(),
        Err(RequestReadError::TimedOut) => {
            log::debug!("Global metrics server request read timed out");
            return;
        }
        Err(RequestReadError::Io(error)) => {
            log::debug!("Global metrics server request read failed: {}", error);
            return;
        }
    };

    if let Err(error) = socket.write_all(response.as_bytes()).await {
        log::debug!("Global metrics response write failed: {}", error);
    }
    if let Err(error) = socket.shutdown().await {
        log::debug!("Global metrics socket shutdown failed: {}", error);
    }
}

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
