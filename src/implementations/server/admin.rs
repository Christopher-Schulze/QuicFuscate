//! Admin control socket for QuicFuscate server.
//!
//! Provides Unix socket interface for quicfuscate-ctl commands.
//!
//! ## Architecture: admin.rs vs admin_http.rs
//!
//! This module (`admin.rs`) is the **Unix domain socket control plane** - a low-level,
//! local-only admin interface designed for `quicfuscate-ctl` CLI commands on the same host.
//! It uses JSON-over-Unix-socket for fast, unauthenticated local control (the socket file
//! permissions provide access control).
//!
//! The sibling module `admin_http.rs` is the **HTTP web dashboard** - a remote-capable,
//! authenticated admin interface that serves the web-admin UI and exposes a JSON API
//! over HTTP with session cookies, CSRF protection, and Argon2 password hashing.
//!
//! Both interfaces serve different use cases and are intentionally parallel:
//! - `admin.rs`: local server management, scripting, automation (no auth overhead)
//! - `admin_http.rs`: remote dashboard access, QKey management, multi-user (authenticated)
//!
//! They share types (`AdminCommand`, `AdminResponse`, `ClientInfo`) defined in this module,
//! but implement handler logic independently. Future direction: extract shared handler
//! logic into a common service layer to reduce duplication while preserving transport
//! separation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(any(test, feature = "rust-tests"))]
use super::metrics::Metrics;

/// Admin command types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum AdminCommand {
    /// Get server status
    #[serde(rename = "status")]
    Status,

    /// List connected clients
    #[serde(rename = "clients")]
    ListClients,

    /// Kick a client by ID
    #[serde(rename = "kick")]
    Kick { id: String },

    /// Block an IP address
    #[serde(rename = "block")]
    Block { ip: String },

    /// Unblock an IP address
    #[serde(rename = "unblock")]
    Unblock { ip: String },

    /// Reload configuration
    #[serde(rename = "reload")]
    Reload,

    /// Generate QKey
    #[serde(rename = "qkey")]
    GenerateQKey,

    /// Shutdown server
    #[serde(rename = "shutdown")]
    Shutdown,
}

/// Admin response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl AdminResponse {
    pub fn ok() -> Self {
        Self { success: true, message: None, data: None }
    }

    pub fn ok_with_message(msg: impl Into<String>) -> Self {
        Self { success: true, message: Some(msg.into()), data: None }
    }

    pub fn ok_with_data(data: serde_json::Value) -> Self {
        Self { success: true, message: None, data: Some(data) }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self { success: false, message: Some(msg.into()), data: None }
    }
}

/// Client info for listing.
#[derive(Debug, Serialize)]
pub struct ClientInfo {
    /// Canonical admin/runtime identity. Session identity is preferred; remote address is legacy compat only.
    pub id: String,
    pub ip: String,
    pub remote_addr: String,
    pub connected_secs: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub stealth_mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClientIdentity {
    Remote(SocketAddr),
    Session(super::session::SessionId),
}

impl ClientIdentity {
    pub fn canonical(
        session_id: Option<super::session::SessionId>,
        remote_addr: SocketAddr,
    ) -> Self {
        session_id.map(Self::Session).unwrap_or_else(|| Self::Remote(remote_addr))
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if let Some(value) = trimmed.strip_prefix("session:") {
            let numeric = value.strip_prefix("Session-").unwrap_or(value);
            return numeric
                .parse::<u64>()
                .ok()
                .map(|id| Self::Session(super::session::SessionId::from_u64(id)));
        }
        if let Some(value) = trimmed.strip_prefix("remote:") {
            return value.parse::<SocketAddr>().ok().map(Self::Remote);
        }
        trimmed.parse::<SocketAddr>().ok().map(Self::Remote)
    }

    pub fn remote(remote_addr: SocketAddr) -> Self {
        Self::Remote(remote_addr)
    }

    pub fn as_remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Remote(addr) => Some(*addr),
            Self::Session(_) => None,
        }
    }
}

impl std::fmt::Display for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Remote(addr) => write!(f, "remote:{}", addr),
            Self::Session(id) => write!(f, "session:{}", id.as_u64()),
        }
    }
}

/// Runtime client snapshot used to derive admin-visible connection state.
#[derive(Clone, Debug)]
pub struct ClientSnapshot {
    connected_at: Instant,
    bytes_in: u64,
    bytes_out: u64,
    stealth_mode: String,
    session_id: Option<super::session::SessionId>,
}

impl ClientSnapshot {
    pub fn new(stealth_mode: String) -> Self {
        Self {
            connected_at: Instant::now(),
            bytes_in: 0,
            bytes_out: 0,
            stealth_mode,
            session_id: None,
        }
    }

    pub fn record_bytes_in(&mut self, bytes: u64, stealth_mode: String) {
        self.bytes_in = self.bytes_in.saturating_add(bytes);
        self.stealth_mode = stealth_mode;
    }

    pub fn record_bytes_out(&mut self, bytes: u64) {
        self.bytes_out = self.bytes_out.saturating_add(bytes);
    }

    pub fn set_session_id(&mut self, session_id: super::session::SessionId) {
        self.session_id = Some(session_id);
    }

    fn to_client_info(&self, remote_addr: SocketAddr, now: Instant) -> ClientInfo {
        ClientInfo {
            id: ClientIdentity::canonical(self.session_id, remote_addr).to_string(),
            ip: remote_addr.ip().to_string(),
            remote_addr: remote_addr.to_string(),
            connected_secs: now.duration_since(self.connected_at).as_secs(),
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            stealth_mode: self.stealth_mode.clone(),
        }
    }
}

pub fn snapshots_to_client_info(
    snapshots: &HashMap<SocketAddr, ClientSnapshot>,
    now: Instant,
) -> Vec<ClientInfo> {
    let mut clients: Vec<ClientInfo> =
        snapshots.iter().map(|(addr, snapshot)| snapshot.to_client_info(*addr, now)).collect();
    clients.sort_unstable_by(|left, right| left.remote_addr.cmp(&right.remote_addr));
    clients
}

/// Admin command handler trait.
pub trait AdminHandler: Send + Sync {
    fn handle_status(&self) -> AdminResponse;
    fn handle_list_clients(&self) -> Vec<ClientInfo>;
    fn handle_kick(&self, id: &str) -> AdminResponse;
    fn handle_block(&self, ip: &str) -> AdminResponse;
    fn handle_unblock(&self, ip: &str) -> AdminResponse;
    fn handle_reload(&self) -> AdminResponse;
    fn handle_qkey(&self) -> String;
    fn handle_shutdown(&self) -> AdminResponse;
}

/// Default admin handler using metrics.
#[cfg(any(test, feature = "rust-tests"))]
pub struct DefaultAdminHandler {
    metrics: Arc<Metrics>,
    blocked_ips: parking_lot::RwLock<std::collections::HashSet<String>>,
}

#[cfg(any(test, feature = "rust-tests"))]
impl DefaultAdminHandler {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics, blocked_ips: parking_lot::RwLock::new(std::collections::HashSet::new()) }
    }

    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocked_ips.read().contains(ip)
    }
}

#[cfg(any(test, feature = "rust-tests"))]
impl AdminHandler for DefaultAdminHandler {
    fn handle_status(&self) -> AdminResponse {
        use std::sync::atomic::Ordering;

        let data = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": self.metrics.uptime_secs(),
            "clients_active": self.metrics.clients_active.load(Ordering::Relaxed),
            "clients_total": self.metrics.clients_total.load(Ordering::Relaxed),
            "connections_accepted": self.metrics.connections_accepted.load(Ordering::Relaxed),
            "connections_rejected": self.metrics.connections_rejected.load(Ordering::Relaxed),
            "auth_failed": self.metrics.auth_failed.load(Ordering::Relaxed),
            "bytes_in": self.metrics.bytes_in.load(Ordering::Relaxed),
            "bytes_out": self.metrics.bytes_out.load(Ordering::Relaxed),
            "stealth": {
                "http3": self.metrics.stealth_http3_active.load(Ordering::Relaxed),
                "tls13": self.metrics.stealth_tls13_active.load(Ordering::Relaxed)
            },
            "fec_recovered": self.metrics.fec_packets_recovered.load(Ordering::Relaxed),
        });

        AdminResponse::ok_with_data(data)
    }

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        // Test-only fallback handler does not own live session state.
        vec![]
    }

    fn handle_kick(&self, id: &str) -> AdminResponse {
        // Test-only fallback handler reports the intent but has no live connection owner.
        log::info!("Admin: Kicking client {}", id);
        AdminResponse::ok_with_message(format!("Client {} disconnected", id))
    }

    fn handle_block(&self, ip: &str) -> AdminResponse {
        self.blocked_ips.write().insert(ip.to_string());
        log::info!("Admin: Blocked IP {}", ip);
        AdminResponse::ok_with_message(format!("IP {} blocked", ip))
    }

    fn handle_unblock(&self, ip: &str) -> AdminResponse {
        if self.blocked_ips.write().remove(ip) {
            log::info!("Admin: Unblocked IP {}", ip);
            AdminResponse::ok_with_message(format!("IP {} unblocked", ip))
        } else {
            AdminResponse::error(format!("IP {} was not blocked", ip))
        }
    }

    fn handle_reload(&self) -> AdminResponse {
        // Test-only fallback handler acknowledges the request without runtime wiring.
        log::info!("Admin: Config reload requested");
        AdminResponse::ok_with_message(
            "Configuration reload accepted; runtime policy changes apply to next connections only",
        )
    }

    fn handle_qkey(&self) -> String {
        // Test-only fallback handler emits a deterministic synthetic server profile.
        use crate::engine::qkey;

        let config =
            qkey::QKeyConfig::new("vpn.example.com:4433", "cdn.example.com").with_stealth("auto");
        let mut nonce = [0u8; 8];
        crate::rng::fill_secure_or_abort(&mut nonce, "admin::handle_qkey_nonce");
        let extra: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
        let mut token_bytes = [0u8; 32];
        crate::rng::fill_secure_or_abort(&mut token_bytes, "admin::handle_qkey_token");
        let token_hex: String = token_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let config = config.with_extra(&format!("nonce={}", extra)).with_token(&token_hex);
        qkey::generate(&config)
    }

    fn handle_shutdown(&self) -> AdminResponse {
        log::info!("Admin: Shutdown requested");
        AdminResponse::ok_with_message("Server shutting down")
    }
}

/// Admin socket server.
#[cfg(unix)]
pub struct AdminServer {
    socket_path: std::path::PathBuf,
    handler: Arc<dyn AdminHandler>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(unix)]
impl AdminServer {
    /// Create a new admin server.
    pub fn new<P: AsRef<std::path::Path>>(socket_path: P, handler: Arc<dyn AdminHandler>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            handler,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Run the admin server.
    pub async fn run(&self) -> std::io::Result<()> {
        // Remove old socket if exists
        if let Err(e) = std::fs::remove_file(&self.socket_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!(
                    "Failed to remove stale admin socket {}: {}",
                    self.socket_path.display(),
                    e
                );
            }
        }

        // Create parent directory
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        log::info!("Admin socket listening on {:?}", self.socket_path);

        while !self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((stream, _addr))) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, handler).await {
                            log::warn!("Admin connection error: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    log::warn!("Admin socket accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        // Cleanup
        if let Err(e) = std::fs::remove_file(&self.socket_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!(
                    "Failed to remove admin socket on shutdown {}: {}",
                    self.socket_path.display(),
                    e
                );
            }
        }
        log::info!("Admin socket stopped");
        Ok(())
    }

    async fn handle_connection(
        stream: UnixStream,
        handler: Arc<dyn AdminHandler>,
    ) -> std::io::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        reader.read_line(&mut line).await?;

        let response = match serde_json::from_str::<AdminCommand>(&line) {
            Ok(cmd) => {
                log::debug!("Admin command: {:?}", cmd);
                match cmd {
                    AdminCommand::Status => handler.handle_status(),
                    AdminCommand::ListClients => {
                        let clients = handler.handle_list_clients();
                        match serde_json::to_value(clients) {
                            Ok(data) => AdminResponse::ok_with_data(data),
                            Err(err) => {
                                AdminResponse::error(format!("Serialize clients failed: {}", err))
                            }
                        }
                    }
                    AdminCommand::Kick { id } => handler.handle_kick(&id),
                    AdminCommand::Block { ip } => handler.handle_block(&ip),
                    AdminCommand::Unblock { ip } => handler.handle_unblock(&ip),
                    AdminCommand::Reload => handler.handle_reload(),
                    AdminCommand::GenerateQKey => {
                        let qkey = handler.handle_qkey();
                        AdminResponse::ok_with_data(serde_json::json!({ "qkey": qkey }))
                    }
                    AdminCommand::Shutdown => handler.handle_shutdown(),
                }
            }
            Err(e) => AdminResponse::error(format!("Invalid command: {}", e)),
        };

        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        Ok(())
    }
}

#[cfg(unix)]
impl Drop for AdminServer {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.socket_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::debug!(
                    "AdminServer drop socket cleanup failed ({}): {}",
                    self.socket_path.display(),
                    e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_command_parse() {
        let json = r#"{"cmd":"status"}"#;
        let cmd: AdminCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, AdminCommand::Status));

        let json = r#"{"cmd":"kick","id":"abc123"}"#;
        let cmd: AdminCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, AdminCommand::Kick { id } if id == "abc123"));
    }

    #[test]
    fn test_admin_response() {
        let resp = AdminResponse::ok();
        assert!(resp.success);

        let resp = AdminResponse::error("test error");
        assert!(!resp.success);
        assert_eq!(resp.message.unwrap(), "test error");
    }

    #[test]
    fn test_default_handler() {
        let metrics = Arc::new(Metrics::new());
        let handler = DefaultAdminHandler::new(metrics);

        let resp = handler.handle_status();
        assert!(resp.success);

        let resp = handler.handle_block("1.2.3.4");
        assert!(resp.success);
        assert!(handler.is_blocked("1.2.3.4"));

        let resp = handler.handle_unblock("1.2.3.4");
        assert!(resp.success);
        assert!(!handler.is_blocked("1.2.3.4"));
    }

    #[test]
    fn test_snapshot_projection_is_sorted_and_preserves_counters() {
        let mut snapshots = HashMap::new();

        let mut later_addr_snapshot = ClientSnapshot::new("mode-b".to_string());
        later_addr_snapshot.record_bytes_in(9, "mode-b".to_string());
        later_addr_snapshot.record_bytes_out(4);
        snapshots.insert("127.0.0.1:9001".parse::<SocketAddr>().unwrap(), later_addr_snapshot);

        let mut earlier_addr_snapshot = ClientSnapshot::new("mode-a".to_string());
        earlier_addr_snapshot.record_bytes_in(3, "mode-a-updated".to_string());
        earlier_addr_snapshot.record_bytes_out(7);
        snapshots.insert("127.0.0.1:9000".parse::<SocketAddr>().unwrap(), earlier_addr_snapshot);

        let clients = snapshots_to_client_info(&snapshots, Instant::now());
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].id, "remote:127.0.0.1:9000");
        assert_eq!(clients[0].remote_addr, "127.0.0.1:9000");
        assert_eq!(clients[0].bytes_in, 3);
        assert_eq!(clients[0].bytes_out, 7);
        assert_eq!(clients[0].stealth_mode, "mode-a-updated");
        assert_eq!(clients[1].id, "remote:127.0.0.1:9001");
        assert_eq!(clients[1].remote_addr, "127.0.0.1:9001");
        assert_eq!(clients[1].bytes_in, 9);
        assert_eq!(clients[1].bytes_out, 4);
        assert_eq!(clients[1].stealth_mode, "mode-b");
    }

    #[test]
    fn test_snapshot_projection_prefers_session_identity_when_available() {
        let mut snapshots = HashMap::new();
        let mut snapshot = ClientSnapshot::new("mode-a".to_string());
        snapshot.set_session_id(super::super::session::SessionId::from_u64(42));
        snapshot.record_bytes_in(3, "mode-a".to_string());
        snapshots.insert("127.0.0.1:9000".parse::<SocketAddr>().unwrap(), snapshot);

        let clients = snapshots_to_client_info(&snapshots, Instant::now());
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, "session:42");
        assert_eq!(clients[0].remote_addr, "127.0.0.1:9000");
    }

    #[test]
    fn test_client_identity_parsing_accepts_canonical_and_legacy_remote_forms() {
        let remote = "127.0.0.1:9443".parse::<SocketAddr>().unwrap();
        assert_eq!(ClientIdentity::parse("127.0.0.1:9443"), Some(ClientIdentity::Remote(remote)));
        assert_eq!(
            ClientIdentity::parse("remote:127.0.0.1:9443"),
            Some(ClientIdentity::Remote(remote))
        );
        assert_eq!(
            ClientIdentity::parse("session:42"),
            Some(ClientIdentity::Session(super::super::session::SessionId::from_u64(42)))
        );
        assert_eq!(
            ClientIdentity::parse("session:Session-42"),
            Some(ClientIdentity::Session(super::super::session::SessionId::from_u64(42)))
        );
        assert_eq!(ClientIdentity::parse(""), None);
    }

    #[test]
    fn test_client_identity_canonical_prefers_session_over_remote() {
        let remote = "127.0.0.1:9443".parse::<SocketAddr>().unwrap();
        assert_eq!(
            ClientIdentity::canonical(Some(super::super::session::SessionId::from_u64(7)), remote),
            ClientIdentity::Session(super::super::session::SessionId::from_u64(7))
        );
        assert_eq!(ClientIdentity::canonical(None, remote), ClientIdentity::Remote(remote));
    }
}
