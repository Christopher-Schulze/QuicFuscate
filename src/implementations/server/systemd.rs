//! Systemd integration for QuicFuscate server.
//!
//! Provides:
//! - Service file generation
//! - Socket activation support
//! - Journal logging
//! - Health check daemon

use std::io::Write;
use std::path::Path;

/// Systemd unit type.
#[derive(Debug, Clone, Copy)]
pub enum UnitType {
    Service,
    Socket,
}

/// Systemd service configuration.
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Service name (without .service)
    pub name: String,
    /// Description
    pub description: String,
    /// Binary path
    pub exec_start: String,
    /// Working directory
    pub working_directory: Option<String>,
    /// User to run as
    pub user: Option<String>,
    /// Group to run as
    pub group: Option<String>,
    /// Restart policy
    pub restart: RestartPolicy,
    /// Restart delay in seconds
    pub restart_sec: u32,
    /// Enable watchdog
    pub watchdog_sec: Option<u32>,
    /// Environment variables
    pub environment: Vec<(String, String)>,
    /// After dependencies
    pub after: Vec<String>,
    /// Wants dependencies
    pub wants: Vec<String>,
    /// Required capabilities
    pub capabilities: Vec<String>,
    /// Enable socket activation
    pub socket_activation: bool,
    /// Health check port (HTTP)
    pub health_port: Option<u16>,
}

/// Restart policy.
#[derive(Clone, Copy, Debug, Default)]
pub enum RestartPolicy {
    #[default]
    OnFailure,
    Always,
    OnAbnormal,
    Never,
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OnFailure => write!(f, "on-failure"),
            Self::Always => write!(f, "always"),
            Self::OnAbnormal => write!(f, "on-abnormal"),
            Self::Never => write!(f, "no"),
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: "quicfuscate".to_string(),
            description: "QuicFuscate VPN Server".to_string(),
            exec_start:
                "/usr/local/bin/quicfuscate --mode server --config /etc/quicfuscate/server.toml"
                    .to_string(),
            working_directory: Some("/var/lib/quicfuscate".to_string()),
            user: None,
            group: None,
            restart: RestartPolicy::OnFailure,
            restart_sec: 5,
            watchdog_sec: Some(30),
            environment: vec![("RUST_LOG".to_string(), "info".to_string())],
            after: vec!["network-online.target".to_string()],
            wants: vec!["network-online.target".to_string()],
            capabilities: vec![
                "CAP_NET_ADMIN".to_string(),
                "CAP_NET_BIND_SERVICE".to_string(),
                "CAP_NET_RAW".to_string(),
                "CAP_CHOWN".to_string(),
                "CAP_SETGID".to_string(),
                "CAP_SETUID".to_string(),
            ],
            socket_activation: false,
            health_port: Some(8080),
        }
    }
}

impl ServiceConfig {
    /// Create a minimal server config.
    pub fn server() -> Self {
        Self::default()
    }

    /// Create a client config.
    pub fn client() -> Self {
        Self {
            name: "quicfuscate-client".to_string(),
            description: "QuicFuscate VPN Client".to_string(),
            exec_start:
                "/usr/local/bin/quicfuscate --mode client --config /etc/quicfuscate/client.toml"
                    .to_string(),
            user: None, // Run as root for TUN
            group: None,
            health_port: None,
            ..Self::default()
        }
    }

    /// Generate the service file content.
    pub fn generate_service(&self) -> String {
        let mut content = String::new();

        // [Unit] section
        content.push_str("[Unit]\n");
        content.push_str(&format!("Description={}\n", self.description));
        content.push_str("Documentation=https://github.com/your-org/quicfuscate\n");

        for dep in &self.after {
            content.push_str(&format!("After={}\n", dep));
        }
        for dep in &self.wants {
            content.push_str(&format!("Wants={}\n", dep));
        }

        content.push('\n');

        // [Service] section
        content.push_str("[Service]\n");
        content.push_str("Type=notify\n");
        content.push_str("NotifyAccess=main\n");
        content.push_str(&format!("ExecStart={}\n", self.exec_start));
        content.push_str("ExecReload=/bin/kill -HUP $MAINPID\n");
        content.push_str("KillSignal=SIGTERM\n");
        content.push_str("TimeoutStopSec=10s\n");

        if let Some(ref wd) = self.working_directory {
            content.push_str(&format!("WorkingDirectory={}\n", wd));
        }

        if let Some(ref user) = self.user {
            content.push_str(&format!("User={}\n", user));
        }
        if let Some(ref group) = self.group {
            content.push_str(&format!("Group={}\n", group));
        }

        content.push_str(&format!("Restart={}\n", self.restart));
        content.push_str(&format!("RestartSec={}\n", self.restart_sec));

        if let Some(watchdog) = self.watchdog_sec {
            content.push_str(&format!("WatchdogSec={}\n", watchdog));
        }

        // Capabilities
        if !self.capabilities.is_empty() {
            let caps = self.capabilities.join(" ");
            if self.user.is_some() {
                content.push_str(&format!("AmbientCapabilities={}\n", caps));
            }
            content.push_str(&format!("CapabilityBoundingSet={}\n", caps));
        }

        // Environment
        for (key, value) in &self.environment {
            content.push_str(&format!("Environment=\"{}={}\"\n", key, value));
        }

        // Security hardening
        content.push_str("\n# Security hardening\n");
        content.push_str("NoNewPrivileges=yes\n");
        content.push_str("ProtectSystem=strict\n");
        content.push_str("ProtectHome=yes\n");
        content.push_str("PrivateTmp=yes\n");
        content.push_str("ProtectKernelTunables=yes\n");
        content.push_str("ProtectKernelModules=yes\n");
        content.push_str("ProtectControlGroups=yes\n");
        content.push_str("RestrictNamespaces=yes\n");
        content.push_str("LockPersonality=yes\n");
        content.push_str("MemoryDenyWriteExecute=yes\n");
        content.push_str("RestrictRealtime=yes\n");

        // Read-write paths
        if let Some(ref wd) = self.working_directory {
            content.push_str(&format!("ReadWritePaths={}\n", wd));
        }
        content.push_str("ReadWritePaths=/dev/net/tun\n");

        content.push('\n');

        // [Install] section
        content.push_str("[Install]\n");
        content.push_str("WantedBy=multi-user.target\n");

        content
    }

    /// Generate socket file for socket activation.
    pub fn generate_socket(&self, port: u16) -> String {
        let mut content = String::new();

        content.push_str("[Unit]\n");
        content.push_str(&format!("Description={} Socket\n", self.description));
        content.push('\n');

        content.push_str("[Socket]\n");
        content.push_str(&format!("ListenDatagram=0.0.0.0:{}\n", port));
        content.push_str("ReusePort=yes\n");
        content.push('\n');

        content.push_str("[Install]\n");
        content.push_str("WantedBy=sockets.target\n");

        content
    }

    /// Write service file to disk.
    pub fn write_service<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let content = self.generate_service();
        let mut file = std::fs::File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Write socket file to disk.
    pub fn write_socket<P: AsRef<Path>>(&self, path: P, port: u16) -> std::io::Result<()> {
        let content = self.generate_socket(port);
        let mut file = std::fs::File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

/// Systemd notify interface.
#[cfg(unix)]
pub mod notify {
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    /// Notify systemd that service is ready.
    pub fn ready() -> std::io::Result<()> {
        send_state("READY=1")
    }

    /// Notify systemd of status.
    pub fn status(msg: &str) -> std::io::Result<()> {
        send_state(&format!("STATUS={}", msg))
    }

    /// Send watchdog ping.
    pub fn watchdog() -> std::io::Result<()> {
        send_state("WATCHDOG=1")
    }

    /// Notify systemd of stopping.
    pub fn stopping() -> std::io::Result<()> {
        send_state("STOPPING=1")
    }

    /// Notify systemd of reload complete.
    pub fn reloading() -> std::io::Result<()> {
        send_state("RELOADING=1")
    }

    /// Return half of systemd's watchdog interval so heartbeats arrive with margin.
    pub fn watchdog_interval() -> Option<Duration> {
        let watchdog_usec = std::env::var("WATCHDOG_USEC").ok()?.parse::<u64>().ok()?;
        if watchdog_usec == 0 {
            return None;
        }
        if let Ok(expected_pid) = std::env::var("WATCHDOG_PID") {
            if expected_pid.parse::<u32>().ok()? != std::process::id() {
                return None;
            }
        }
        Some(Duration::from_micros((watchdog_usec / 2).max(1)))
    }

    fn send_state(state: &str) -> std::io::Result<()> {
        let socket_path = match std::env::var("NOTIFY_SOCKET") {
            Ok(path) => path,
            Err(_) => return Ok(()), // Not running under systemd
        };

        let socket = UnixDatagram::unbound()?;

        if socket_path.starts_with('@') {
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                let abstract_name = socket_path.strip_prefix('@').unwrap_or_default();
                let address = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name)?;
                socket.send_to_addr(state.as_bytes(), &address)?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "abstract Unix sockets are unsupported on this platform",
                ));
            }
        } else {
            socket.send_to(state.as_bytes(), socket_path)?;
        }
        Ok(())
    }
}

/// Health check HTTP server.
pub mod health {
    use super::super::http::{read_request, RequestReadError, MAX_CONCURRENT_CONNECTIONS};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    fn parse_request_line(req: &str) -> Option<(&str, &str)> {
        let mut lines = req.lines();
        let line = lines.next()?.trim();
        let mut parts = line.split_whitespace();
        let method = parts.next()?;
        let path = parts.next()?;
        Some((method, path))
    }

    fn http_response(status: u16, body: &str) -> String {
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Payload Too Large",
            503 => "Service Unavailable",
            _ => "Internal Server Error",
        };
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            reason,
            body.len(),
            body
        )
    }

    fn memory_lock_response(path: &str) -> (u16, String) {
        let memory_lock = crate::memory_lock::current_status();
        let status = if path == "/live" { "ok" } else { memory_lock.health_status() };
        let response_status =
            if path == "/live" || !memory_lock.is_not_ready() { 200 } else { 503 };
        (
            response_status,
            serde_json::json!({
                "status": status,
                "memory_lock": memory_lock.health_json(),
            })
            .to_string(),
        )
    }

    async fn handle_connection(mut socket: TcpStream) {
        let response = match read_request(&mut socket).await {
            Ok(Some(request)) => {
                let req_str = String::from_utf8_lossy(&request);
                let (status, body) = match parse_request_line(&req_str) {
                    Some(("GET", path)) if matches!(path, "/health" | "/ready" | "/live") => {
                        memory_lock_response(path)
                    }
                    Some(("GET", _)) => (404, "{\"error\":\"not_found\"}".to_string()),
                    Some((_, _)) => (405, "{\"error\":\"method_not_allowed\"}".to_string()),
                    None => (400, "{\"error\":\"bad_request\"}".to_string()),
                };
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    http_response(status, &body)
                } else {
                    http_response(400, "{\"error\":\"bad_request\"}")
                }
            }
            Ok(None) => return,
            Err(RequestReadError::Incomplete) => http_response(400, "{\"error\":\"bad_request\"}"),
            Err(RequestReadError::TooLarge) => {
                http_response(413, "{\"error\":\"request_too_large\"}")
            }
            Err(RequestReadError::TimedOut) => {
                log::debug!("Health server request read timed out");
                return;
            }
            Err(RequestReadError::Io(error)) => {
                log::debug!("Health server request read failed: {}", error);
                return;
            }
        };
        if let Err(error) = socket.write_all(response.as_bytes()).await {
            log::debug!("Health server response write failed: {}", error);
        }
        if let Err(error) = socket.shutdown().await {
            log::debug!("Health server socket shutdown failed: {}", error);
        }
    }

    /// Health check server.
    pub struct HealthServer {
        addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
    }

    impl HealthServer {
        /// Create a new health server.
        pub fn new(port: u16) -> Self {
            Self {
                addr: SocketAddr::from(([0, 0, 0, 0], port)),
                shutdown: Arc::new(AtomicBool::new(false)),
            }
        }

        /// Get shutdown signal.
        pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
            self.shutdown.clone()
        }

        /// Shutdown the server.
        pub fn shutdown(&self) {
            self.shutdown.store(true, Ordering::SeqCst);
        }

        async fn run_listener(&self, listener: TcpListener) -> std::io::Result<()> {
            let connection_slots =
                Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
            while !self.shutdown.load(Ordering::Relaxed) {
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    listener.accept(),
                )
                .await
                {
                    Ok(Ok((socket, _addr))) => {
                        let permit = match connection_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => continue,
                        };
                        tokio::spawn(async move {
                            handle_connection(socket).await;
                            drop(permit);
                        });
                    }
                    Ok(Err(e)) => {
                        log::warn!("Health server accept error: {}", e);
                    }
                    Err(_) => {
                        // Timeout, check shutdown.
                    }
                }
            }
            Ok(())
        }

        /// Run the health check server.
        pub async fn run(&self) -> std::io::Result<()> {
            let listener = TcpListener::bind(self.addr).await?;
            log::info!("Health check server listening on {}", self.addr);

            let result = self.run_listener(listener).await;
            log::info!("Health check server stopped");
            result
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;
        use tokio::io::AsyncReadExt as _;

        #[tokio::test]
        async fn half_open_connection_does_not_block_next_health_probe() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let shutdown = Arc::new(AtomicBool::new(false));
            let server = HealthServer { addr, shutdown: shutdown.clone() };
            let server_task = tokio::spawn(async move { server.run_listener(listener).await });

            let stalled = TcpStream::connect(addr).await.unwrap();
            let mut valid = TcpStream::connect(addr).await.unwrap();
            valid.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), valid.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();

            assert!(response.starts_with(b"HTTP/1.1 200 OK"));
            drop(stalled);
            shutdown.store(true, Ordering::SeqCst);
            server_task.await.unwrap().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config_default() {
        let config = ServiceConfig::default();
        assert_eq!(config.name, "quicfuscate");
        assert_eq!(config.restart_sec, 5);
    }

    #[test]
    fn test_generate_service() {
        let config = ServiceConfig::default();
        let content = config.generate_service();

        assert!(content.contains("[Unit]"));
        assert!(content.contains("[Service]"));
        assert!(content.contains("[Install]"));
        assert!(content.contains("Type=notify"));
        assert!(content.contains("NotifyAccess=main"));
        assert!(content.contains("ExecReload=/bin/kill -HUP $MAINPID"));
        assert!(content.contains("KillSignal=SIGTERM"));
        assert!(content.contains("TimeoutStopSec=10s"));
        assert!(content.contains("CapabilityBoundingSet="));
        assert!(!content.contains("AmbientCapabilities="));
        assert!(content.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn non_root_service_uses_ambient_capabilities() {
        let config =
            ServiceConfig { user: Some("quicfuscate".to_string()), ..ServiceConfig::default() };

        let content = config.generate_service();

        assert!(content.contains("AmbientCapabilities="));
        assert!(content.contains("CapabilityBoundingSet="));
    }

    #[test]
    fn test_generate_socket() {
        let config = ServiceConfig::default();
        let content = config.generate_socket(4433);

        assert!(content.contains("[Socket]"));
        assert!(content.contains("ListenDatagram=0.0.0.0:4433"));
    }

    #[test]
    fn test_client_config() {
        let config = ServiceConfig::client();
        assert_eq!(config.name, "quicfuscate-client");
        assert!(config.user.is_none());
    }
}
