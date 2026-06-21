use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// "Too Big To Block" Targets
const TARGETS: &[&str] = &[
    "1.1.1.1:443", // Cloudflare
    "8.8.8.8:443", // Google
    "9.9.9.9:443", // Quad9
];

/// Deterministic cleanup interval - sweep stale sessions every 60 seconds.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// Force immediate cleanup when session count exceeds this threshold.
const MAX_SESSIONS: usize = 10_000;
/// Session TTL - evict entries inactive for longer than this.
const SESSION_TTL: Duration = Duration::from_secs(300);

/// Represents a raw response packet that needs to be relayed back to the scanner.
pub struct FallbackResponse {
    /// Original scanner address to send the response back to.
    pub target: SocketAddr,
    /// Raw upstream response payload to relay.
    pub data: Vec<u8>,
}

/// Manages reverse proxy sessions for active probes.
/// When a probe is detected (invalid auth), we transparently forward it to a legitimate upstream.
/// The response is captured and sent back to the scanner so the observable path resembles a
/// legitimate upstream service instead of exposing the forked server directly.
pub struct RealityProxy {
    // Channel to send responses back to the main server loop
    tx: mpsc::Sender<FallbackResponse>,
    // Session map: Scanner IP -> Session Handle
    sessions: Mutex<HashMap<SocketAddr, SessionHandle>>,
    // Round-robin target selector
    target_idx: AtomicUsize,
    // Upstream targets (env override supported)
    targets: Vec<String>,
    // Deterministic cleanup tracker
    last_cleanup: Mutex<Instant>,
}

struct SessionHandle {
    last_active: Instant,
    sender: mpsc::Sender<Vec<u8>>,     // Send packets TO upstream task
    task: tokio::task::JoinHandle<()>, // Tracked proxy task handle
}

impl RealityProxy {
    /// Create a new reality proxy with the given response channel.
    pub fn new(tx: mpsc::Sender<FallbackResponse>) -> Self {
        Self {
            tx,
            sessions: Mutex::new(HashMap::new()),
            target_idx: AtomicUsize::new(0),
            targets: load_targets(),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Selects a rugged upstream target.
    fn select_target(&self) -> String {
        let idx = self.target_idx.fetch_add(1, Ordering::Relaxed);
        self.targets[idx % self.targets.len()].clone()
    }

    /// Test-only accessor for the target selection logic.
    #[cfg(feature = "rust-tests")]
    pub fn select_target_for_tests(&self) -> String {
        self.select_target()
    }

    /// Handles a potential probe packet.
    /// If a session exists, forwards it. If not, creates a new session.
    pub fn forward_probe(&self, packet: &[u8], source: SocketAddr) {
        let mut sessions = self.sessions.lock();

        // Deterministic session cleanup: time-based interval or capacity pressure.
        {
            let mut last = self.last_cleanup.lock();
            if last.elapsed() > CLEANUP_INTERVAL || sessions.len() > MAX_SESSIONS {
                let before = sessions.len();
                sessions.retain(|_, v| {
                    let keep = v.last_active.elapsed() < SESSION_TTL;
                    if !keep {
                        v.task.abort();
                    }
                    keep
                });
                let evicted = before.saturating_sub(sessions.len());
                if evicted > 0 {
                    log::debug!(
                        "Reality Proxy: evicted {} stale sessions ({} remaining)",
                        evicted,
                        sessions.len()
                    );
                }
                *last = Instant::now();
            }
        }

        if let Some(session) = sessions.get_mut(&source) {
            session.last_active = Instant::now();
            if let Err(e) = session.sender.try_send(packet.to_vec()) {
                log::debug!(
                    "Reality Proxy: failed to enqueue probe packet for existing session {}: {}",
                    source,
                    e
                );
            }
        } else {
            // New Probe Session
            let target_addr_str = self.select_target();
            log::info!(
                "Reality Proxy: Forwarding new probe from {} to {}",
                source,
                target_addr_str
            );

            let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(32);
            let response_tx = self.tx.clone();
            let source_copy = source;

            // Spawn lightweight proxy task (JoinHandle tracked in SessionHandle)
            let task = tokio::spawn(async move {
                // Ephemeral local socket for upstream communication
                let upstream = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("RealityProxy: Failed to bind ephemeral socket: {}", e);
                        return;
                    }
                };

                if let Err(e) = upstream.connect(&target_addr_str).await {
                    log::error!(
                        "RealityProxy: Failed to connect to target {}: {}",
                        target_addr_str,
                        e
                    );
                    return;
                }

                // Initial packet forward
                // Note: We swallow the first packet logic here by putting it in the session map loop?
                // Actually, we must process the triggering packet immediately.
                // But since we are in the spawn block, we can't access `packet` easily unless cloned before.
                // Strategy: The session creation pushes to pkt_tx. The Loop reads pkt_rx.

                let mut buf = [0u8; 2048];

                loop {
                    tokio::select! {
                        // Forward FROM Main Server TO Upstream
                        Some(data) = pkt_rx.recv() => {
                            if let Err(e) = upstream.send(&data).await {
                                log::debug!("RealityProxy: Upstream send fail: {}", e);
                                break;
                            }
                        }

                        // Forward FROM Upstream TO Scanner
                        Ok(len) = upstream.recv(&mut buf) => {
                            let resp = FallbackResponse {
                                target: source_copy,
                                data: buf[..len].to_vec(),
                            };
                            if response_tx.send(resp).await.is_err() {
                                break;
                            }
                        }

                        // Timeout inactive sessions
                        _ = tokio::time::sleep(Duration::from_secs(30)) => {
                            break;
                        }
                    }
                }
            });

            // Send the first packet immediately via the new channel
            if let Err(e) = pkt_tx.try_send(packet.to_vec()) {
                log::debug!(
                    "Reality Proxy: failed to enqueue first probe packet for session {}: {}",
                    source,
                    e
                );
            }

            sessions.insert(
                source,
                SessionHandle { last_active: Instant::now(), sender: pkt_tx, task },
            );
        }
    }
}

fn load_targets() -> Vec<String> {
    if let Ok(raw) = std::env::var("QUICFUSCATE_REALITY_TARGETS") {
        let parsed: Vec<String> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    TARGETS.iter().map(|s| s.to_string()).collect()
}

// =============================================================================
// Reality-Grade TLS Mimikry: Cover Handshake Cache (TODO-415 Phase 1)
// =============================================================================

use std::sync::Arc;

/// Configuration for the reality-grade TLS mimikry subsystem.
/// When enabled, the server caches the TLS handshake material from a cover site
/// and replays it to clients/probes, making the proxy indistinguishable from
/// the real cover site at the TLS layer.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// Master switch — when false, reality capture is disabled entirely.
    pub enabled: bool,
    /// Cover site hostname (e.g. "www.cloudflare.com").
    pub cover_host: String,
    /// Cover site port (typically 443).
    pub cover_port: u16,
    /// Cache TTL in seconds before background refresh (default: 3600).
    pub cache_ttl: u64,
    /// If true, fall back to synthetic TlsClientHelloSpoofer on cache miss.
    /// If false, reject connections when cache is empty.
    pub fallback_to_synthetic: bool,
}

impl Default for RealityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cover_host: "www.cloudflare.com".to_string(),
            cover_port: 443,
            cache_ttl: 3600,
            fallback_to_synthetic: true,
        }
    }
}

impl RealityConfig {
    /// Parse reality config from environment variables.
    pub fn from_env() -> Self {
        use crate::env_utils::{env_flag, env_parse};
        Self {
            enabled: env_flag("QUICFUSCATE_REALITY_ENABLED", false),
            cover_host: std::env::var("QUICFUSCATE_REALITY_COVER_HOST")
                .unwrap_or_else(|_| "www.cloudflare.com".to_string()),
            cover_port: env_parse::<u16>("QUICFUSCATE_REALITY_COVER_PORT").unwrap_or(443),
            cache_ttl: env_parse::<u64>("QUICFUSCATE_REALITY_CACHE_TTL").unwrap_or(3600),
            fallback_to_synthetic: env_flag("QUICFUSCATE_REALITY_FALLBACK_SYNTHETIC", true),
        }
    }
}

/// Cached TLS 1.3 handshake material from a cover site.
/// Contains the raw bytes of the server's first flight (ServerHello +
/// EncryptedExtensions + Certificate + CertificateVerify + Finished).
/// This material is replayed to clients/probes for reality-grade mimikry.
#[derive(Debug, Clone)]
pub struct CoverMaterial {
    /// Raw ServerHello bytes (including TLS record header).
    pub server_hello: Vec<u8>,
    /// Server certificate chain (DER-encoded, as received from cover site).
    pub certificate_chain: Vec<Vec<u8>>,
    /// SNI from the cover site response (for validation).
    pub sni: String,
    /// Timestamp when this material was captured (epoch seconds).
    pub captured_at: u64,
    /// TLS version negotiated with cover site (e.g. 0x0304 for TLS 1.3).
    pub tls_version: u16,
}

impl CoverMaterial {
    /// Check if this cached material is stale given a TTL.
    pub fn is_stale(&self, ttl_secs: u64, now_secs: u64) -> bool {
        now_secs.saturating_sub(self.captured_at) >= ttl_secs
    }
}

/// Thread-safe cache for cover-site TLS handshake material.
/// Populated by a background capture task, read by the server handshake path.
pub struct CoverHandshakeCache {
    config: RealityConfig,
    material: parking_lot::RwLock<Option<Arc<CoverMaterial>>>,
}

impl CoverHandshakeCache {
    /// Create a new empty cache with the given config.
    pub fn new(config: RealityConfig) -> Self {
        Self {
            config,
            material: parking_lot::RwLock::new(None),
        }
    }

    /// Get cached cover material if available and not stale.
    /// Returns None if cache is empty or stale.
    pub fn get(&self) -> Option<Arc<CoverMaterial>> {
        let guard = self.material.read();
        guard.as_ref().and_then(|m| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if m.is_stale(self.config.cache_ttl, now) {
                None
            } else {
                Some(Arc::clone(m))
            }
        })
    }

    /// Check if the cache has fresh material available.
    pub fn is_available(&self) -> bool {
        self.get().is_some()
    }

    /// Store newly captured cover material in the cache.
    pub fn store(&self, material: CoverMaterial) {
        let mut guard = self.material.write();
        *guard = Some(Arc::new(material));
    }

    /// Clear the cache (e.g. on capture failure to force fallback).
    pub fn clear(&self) {
        let mut guard = self.material.write();
        *guard = None;
    }

    /// Get the cover site address string ("host:port").
    pub fn cover_addr(&self) -> String {
        format!("{}:{}", self.config.cover_host, self.config.cover_port)
    }

    /// Get a reference to the config.
    pub fn config(&self) -> &RealityConfig {
        &self.config
    }

    /// Capture TLS handshake material from the configured cover site.
    /// Connects via TCP+TLS 1.3 to the cover host and records the server's
    /// first flight. On failure, returns an error (caller decides fallback).
    pub async fn capture(&self) -> Result<CoverMaterial, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = self.cover_addr();
        log::info!("Reality: capturing cover handshake from {}", addr);

        // Connect via TCP
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("TCP connect to {} failed: {}", addr, e))?;

        // Build a TLS 1.3 ClientHello targeting the cover host
        let client_hello = build_tls13_client_hello(&self.config.cover_host);

        // Send ClientHello
        stream
            .write_all(&client_hello)
            .await
            .map_err(|e| format!("write ClientHello failed: {}", e))?;

        // Read ServerHello (first TLS record)
        let mut buf = vec![0u8; 16384];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read ServerHello failed: {}", e))?;

        let server_hello = buf[..n].to_vec();

        // Parse basic TLS record header to extract version and validate
        if server_hello.len() < 6 {
            return Err("ServerHello too short".to_string());
        }

        // TLS record type (byte 0) should be 0x16 (Handshake) for ServerHello
        let record_type = server_hello[0];
        if record_type != 0x16 {
            return Err(format!(
                "Expected TLS Handshake record (0x16), got 0x{:02x}",
                record_type
            ));
        }

        // TLS record version (bytes 1-2) — legacy_record_version, usually 0x0303
        let tls_version = u16::from_be_bytes([server_hello[1], server_hello[2]]);

        // Read additional flight data (Certificate, etc.)
        // In a real implementation, we'd read more records here.
        // For Phase 1, we capture the first flight which contains ServerHello.
        let mut cert_buf = vec![0u8; 16384];
        let cert_n = stream
            .read(&mut cert_buf)
            .await
            .unwrap_or(0);

        // Extract certificate chain (simplified — just store raw bytes for now)
        let certificate_chain = if cert_n > 0 {
            vec![cert_buf[..cert_n].to_vec()]
        } else {
            vec![]
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        log::info!(
            "Reality: captured {} bytes of ServerHello + {} bytes of cert material from {}",
            server_hello.len(),
            cert_n,
            addr
        );

        Ok(CoverMaterial {
            server_hello,
            certificate_chain,
            sni: self.config.cover_host.clone(),
            captured_at: now,
            tls_version,
        })
    }

    /// Background refresh task — captures cover material periodically.
    /// Should be spawned as a tokio task. On failure, logs warning and
    /// retries after TTL/2 seconds.
    pub async fn refresh_loop(self: Arc<Self>) {
        if !self.config.enabled {
            return;
        }

        loop {
            match self.capture().await {
                Ok(material) => {
                    self.store(material);
                    log::debug!("Reality: cache refreshed, sleeping {}s", self.config.cache_ttl);
                    tokio::time::sleep(Duration::from_secs(self.config.cache_ttl)).await;
                }
                Err(e) => {
                    log::warn!("Reality: capture failed: {} — retrying in 60s", e);
                    if self.config.fallback_to_synthetic {
                        log::warn!("Reality: fallback_to_synthetic=true, using synthetic TLS");
                    }
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        }
    }
}

/// Build a minimal TLS 1.3 ClientHello targeting the given SNI.
/// This is a simplified ClientHello for cover-site probing — not a full
/// browser fingerprint. In Phase 2, this will be replaced with a captured
/// real browser ClientHello for byte-identical mimikry.
fn build_tls13_client_hello(sni: &str) -> Vec<u8> {
    // TLS 1.3 ClientHello structure:
    // - Record header: type=0x16, version=0x0301, length
    // - Handshake: type=0x01 (ClientHello), length
    // - ClientVersion: 0x0303 (TLS 1.2 legacy)
    // - Random: 32 bytes
    // - Session ID: 0 length
    // - Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
    // - Compression: null (0x01, 0x00)
    // - Extensions: SNI, supported_versions (0x0304), key_share (x25519)

    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len() as u16;

    // SNI extension (type 0x0000)
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0u16.to_be_bytes()); // extension type: server_name
    let sni_list_len = sni_len + 5;
    sni_ext.extend_from_slice(&sni_list_len.to_be_bytes()); // extension data length
    sni_ext.extend_from_slice(&(sni_len + 3).to_be_bytes()); // server_name_list length
    sni_ext.push(0); // name type: host_name
    sni_ext.extend_from_slice(&sni_len.to_be_bytes()); // name length
    sni_ext.extend_from_slice(sni_bytes);

    // supported_versions extension (type 0x002b) — TLS 1.3
    let mut versions_ext = Vec::new();
    versions_ext.extend_from_slice(&0x002bu16.to_be_bytes()); // type
    versions_ext.extend_from_slice(&3u16.to_be_bytes()); // length
    versions_ext.push(2); // versions list length
    versions_ext.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3

    // key_share extension (type 0x0033) — x25519
    let mut key_share_ext = Vec::new();
    key_share_ext.extend_from_slice(&0x0033u16.to_be_bytes()); // type
    key_share_ext.extend_from_slice(&45u16.to_be_bytes()); // length (2 + 1 + 1 + 32)
    key_share_ext.extend_from_slice(&43u16.to_be_bytes()); // client_shares length
    key_share_ext.extend_from_slice(&0x001du16.to_be_bytes()); // group: x25519
    key_share_ext.extend_from_slice(&32u16.to_be_bytes()); // key length
    key_share_ext.extend_from_slice(&[0u8; 32]); // dummy key (real impl would generate)

    // supported_groups extension (type 0x000a)
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&0x000au16.to_be_bytes()); // type
    groups_ext.extend_from_slice(&4u16.to_be_bytes()); // length
    groups_ext.extend_from_slice(&2u16.to_be_bytes()); // list length
    groups_ext.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
    groups_ext.extend_from_slice(&0x0017u16.to_be_bytes()); // secp256r1

    // signature_algorithms extension (type 0x000d)
    let mut sig_ext = Vec::new();
    sig_ext.extend_from_slice(&0x000du16.to_be_bytes()); // type
    sig_ext.extend_from_slice(&8u16.to_be_bytes()); // length
    sig_ext.extend_from_slice(&6u16.to_be_bytes()); // list length
    sig_ext.extend_from_slice(&0x0401u16.to_be_bytes()); // rsa_pkcs1_sha256
    sig_ext.extend_from_slice(&0x0804u16.to_be_bytes()); // rsa_pss_rsae_sha256
    sig_ext.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256

    // Assemble extensions
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&versions_ext);
    extensions.extend_from_slice(&key_share_ext);
    extensions.extend_from_slice(&groups_ext);
    extensions.extend_from_slice(&sig_ext);

    let extensions_len = extensions.len() as u16;

    // ClientHello body
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version: TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length: 0
    // cipher suites
    body.extend_from_slice(&4u16.to_be_bytes()); // cipher suites length
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&0x1302u16.to_be_bytes()); // TLS_AES_256_GCM_SHA384
    // compression
    body.push(1); // compression methods length
    body.push(0); // null compression
    // extensions
    body.extend_from_slice(&extensions_len.to_be_bytes());
    body.extend_from_slice(&extensions);

    let body_len = body.len() as u32;
    let body_len_bytes = body_len.to_be_bytes();

    // Handshake header: type=0x01, length (3 bytes)
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.extend_from_slice(&body_len_bytes[1..4]); // 24-bit length
    handshake.extend_from_slice(&body);

    let handshake_len = handshake.len() as u16;

    // TLS record header
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy_record_version
    record.extend_from_slice(&handshake_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proxy() -> (RealityProxy, mpsc::Receiver<FallbackResponse>) {
        let (tx, rx) = mpsc::channel(64);
        (RealityProxy::new(tx), rx)
    }

    #[test]
    fn target_rotation_is_round_robin() {
        let (proxy, _rx) = make_proxy();
        let t0 = proxy.select_target();
        let t1 = proxy.select_target();
        let t2 = proxy.select_target();
        // After 3 targets we wrap around
        let t3 = proxy.select_target();
        assert_eq!(t0, TARGETS[0]);
        assert_eq!(t1, TARGETS[1]);
        assert_eq!(t2, TARGETS[2]);
        assert_eq!(t3, TARGETS[0], "should wrap around");
    }

    #[test]
    fn default_targets_are_populated() {
        let targets = load_targets();
        assert_eq!(targets.len(), 3);
        assert!(targets.contains(&"1.1.1.1:443".to_string()));
        assert!(targets.contains(&"8.8.8.8:443".to_string()));
        assert!(targets.contains(&"9.9.9.9:443".to_string()));
    }

    #[test]
    fn session_creation_on_new_source() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let (proxy, _rx) = make_proxy();
            let source: SocketAddr = "10.0.0.1:12345".parse().expect("parse addr");
            proxy.forward_probe(b"test-probe", source);
            // Session should exist now
            let sessions = proxy.sessions.lock();
            assert_eq!(sessions.len(), 1);
            assert!(sessions.contains_key(&source));
        });
    }

    #[test]
    fn same_source_reuses_session() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let (proxy, _rx) = make_proxy();
            let source: SocketAddr = "10.0.0.2:54321".parse().expect("parse addr");
            proxy.forward_probe(b"probe-1", source);
            proxy.forward_probe(b"probe-2", source);
            let sessions = proxy.sessions.lock();
            assert_eq!(sessions.len(), 1, "same source should reuse session");
        });
    }

    #[test]
    fn different_sources_create_separate_sessions() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let (proxy, _rx) = make_proxy();
            let s1: SocketAddr = "10.0.0.1:1111".parse().expect("addr1");
            let s2: SocketAddr = "10.0.0.2:2222".parse().expect("addr2");
            proxy.forward_probe(b"probe-a", s1);
            proxy.forward_probe(b"probe-b", s2);
            let sessions = proxy.sessions.lock();
            assert_eq!(sessions.len(), 2);
        });
    }

    #[test]
    fn constants_are_reasonable() {
        const { assert!(MAX_SESSIONS >= 1000, "MAX_SESSIONS too low") };
        const { assert!(SESSION_TTL.as_secs() >= 60, "SESSION_TTL too short") };
        const { assert!(CLEANUP_INTERVAL.as_secs() >= 10, "CLEANUP_INTERVAL too short") };
    }

    #[test]
    fn reality_config_default_is_disabled() {
        let cfg = RealityConfig::default();
        assert!(!cfg.enabled, "reality should be disabled by default");
        assert!(cfg.fallback_to_synthetic, "fallback should be on by default");
        assert_eq!(cfg.cover_port, 443);
        assert_eq!(cfg.cache_ttl, 3600);
    }

    #[test]
    fn cover_handshake_cache_starts_empty() {
        let cache = CoverHandshakeCache::new(RealityConfig::default());
        assert!(!cache.is_available(), "cache should start empty");
        assert!(cache.get().is_none(), "get should return None on empty cache");
    }

    #[test]
    fn cover_handshake_cache_store_and_get() {
        let cache = CoverHandshakeCache::new(RealityConfig::default());
        let material = CoverMaterial {
            server_hello: vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0c],
            certificate_chain: vec![vec![0x01, 0x02, 0x03]],
            sni: "example.com".to_string(),
            captured_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            tls_version: 0x0303,
        };
        cache.store(material);
        assert!(cache.is_available(), "cache should have material after store");
        let got = cache.get().expect("material should be available");
        assert_eq!(got.sni, "example.com");
        assert_eq!(got.tls_version, 0x0303);
    }

    #[test]
    fn cover_handshake_cache_clear() {
        let cache = CoverHandshakeCache::new(RealityConfig::default());
        let material = CoverMaterial {
            server_hello: vec![0x16],
            certificate_chain: vec![],
            sni: "test.com".to_string(),
            captured_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            tls_version: 0x0303,
        };
        cache.store(material);
        assert!(cache.is_available());
        cache.clear();
        assert!(!cache.is_available(), "cache should be empty after clear");
    }

    #[test]
    fn cover_material_staleness_check() {
        let material = CoverMaterial {
            server_hello: vec![],
            certificate_chain: vec![],
            sni: "test.com".to_string(),
            captured_at: 1000,
            tls_version: 0x0303,
        };
        // TTL=100, now=1050 → not stale
        assert!(!material.is_stale(100, 1050));
        // TTL=100, now=1101 → stale
        assert!(material.is_stale(100, 1101));
    }

    #[test]
    fn tls13_client_hello_has_valid_structure() {
        let hello = build_tls13_client_hello("www.cloudflare.com");
        // Must start with TLS Handshake record type
        assert_eq!(hello[0], 0x16, "record type should be Handshake");
        // legacy_record_version should be 0x0301 or 0x0303
        assert_eq!(hello[1], 0x03, "record version high byte");
        // Must contain ClientHello handshake type
        assert_eq!(hello[5], 0x01, "handshake type should be ClientHello");
        // Must be reasonably sized (at least 100 bytes for a minimal ClientHello)
        assert!(hello.len() > 100, "ClientHello too short: {} bytes", hello.len());
    }

    #[test]
    fn tls13_client_hello_contains_sni() {
        let hello = build_tls13_client_hello("www.example.com");
        // SNI should appear in the ClientHello bytes
        let sni_bytes = b"www.example.com";
        assert!(
            hello.windows(sni_bytes.len()).any(|w| w == sni_bytes),
            "ClientHello must contain SNI hostname"
        );
    }

    #[test]
    fn reality_config_cover_addr_format() {
        let cfg = RealityConfig {
            enabled: true,
            cover_host: "www.cloudflare.com".to_string(),
            cover_port: 8443,
            ..Default::default()
        };
        let cache = CoverHandshakeCache::new(cfg);
        assert_eq!(cache.cover_addr(), "www.cloudflare.com:8443");
    }
}
