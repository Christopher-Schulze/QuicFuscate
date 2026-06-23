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

    /// Inject a pre-built fallback response directly, bypassing the upstream
    /// relay. Used by the reality-grade TLS mimikry path (TODO-415) to serve
    /// cached cover-site handshake material to probes without connecting to
    /// an upstream host.
    ///
    /// Synchronous: uses `try_send` to avoid spawning a tokio task per probe.
    /// The channel has capacity 64; if full (backpressure), the response is
    /// dropped with a debug log — preferable to blocking the recv hot path.
    pub fn send_cached_response(&self, target: SocketAddr, data: Vec<u8>) {
        let resp = FallbackResponse { target, data };
        if let Err(e) = self.tx.try_send(resp) {
            log::debug!("RealityProxy: failed to send cached response: {}", e);
        }
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
    /// Full raw TLS flight bytes (ServerHello + encrypted flight) as captured
    /// from the cover site. Used by Phase 3 probe-resistance to serve a
    /// byte-identical cover-site response to active probes.
    pub raw_flight: Vec<u8>,
    /// Raw ClientHello bytes that the client sent to the cover site during
    /// capture. Used by Phase 2 (ClientHello-Mirror) — the QuicFuscate client
    /// sends a byte-identical ClientHello to the server, making client→server
    /// traffic indistinguishable from client→cover-site traffic.
    pub client_hello: Vec<u8>,
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
    ///
    /// Connects via TCP and completes a full TLS 1.3 handshake using `tokio-rustls`
    /// with a wrapping stream that records the raw server flight bytes (ServerHello +
    /// EncryptedExtensions + Certificate + CertificateVerify + Finished) before
    /// decryption. This yields byte-identical cover-site handshake material that can
    /// be replayed to clients/probes for reality-grade mimikry.
    ///
    /// On failure, returns an error (caller decides fallback per `fallback_to_synthetic`).
    pub async fn capture(&self) -> Result<CoverMaterial, String> {
        use tokio::net::TcpStream;
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let addr = self.cover_addr();
        log::info!("Reality: capturing cover handshake from {}", addr);

        // Build a rustls client config with system roots + webpki fallback.
        // We accept the cover site's real certificate — we only need the raw
        // handshake bytes for replay, not the private key.
        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        if native.certs.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for cert in native.certs {
                let _ = roots.add(cert);
            }
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(config));

        // Connect TCP and wrap with a capturing layer that records raw inbound bytes.
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("TCP connect to {} failed: {}", addr, e))?;
        let server_name =
            rustls::pki_types::ServerName::try_from(self.config.cover_host.clone())
                .map_err(|e| format!("invalid cover_host: {}", e))?;
        let (capturing, capture_rx) = capturing_stream(tcp);
        let tls = connector.connect(server_name, capturing).await.map_err(|e| {
            format!("TLS handshake with {} failed: {}", addr, e)
        })?;

        // In TLS 1.3 the server sends its full first flight (ServerHello +
        // encrypted EncryptedExtensions/Certificate/CertificateVerify/Finished)
        // immediately after processing the ClientHello, without waiting for
        // client application data. The handshake is therefore already complete
        // at this point and all server-flight bytes have been captured by the
        // CapturingStream wrapper.
        //
        // CRITICAL: we must drop `tls` BEFORE calling `capture_rx.collect()`.
        // `collect()` awaits a oneshot receiver that is only fulfilled when
        // `CapturingStream::drop` runs — and `CapturingStream` is owned by
        // `tls`. Without the explicit drop, `collect()` would deadlock.
        drop(tls);
        let captured = capture_rx.collect().await;
        let raw = captured.inbound;

        // Parse the raw TLS records to extract ServerHello and certificate material.
        let (server_hello, certificate_chain, tls_version) =
            parse_raw_tls_flight(&raw).ok_or_else(|| {
                format!("failed to parse TLS flight from {} ({} bytes)", addr, raw.len())
            })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        log::info!(
            "Reality: captured {} bytes of ServerHello + {} cert records ({} bytes total flight, {} bytes ClientHello) from {}",
            server_hello.len(),
            certificate_chain.len(),
            raw.len(),
            captured.outbound.len(),
            addr
        );

        Ok(CoverMaterial {
            server_hello,
            raw_flight: raw,
            client_hello: captured.outbound,
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

// =============================================================================
// CapturingStream — wraps a TcpStream and records raw inbound AND outbound bytes
// =============================================================================

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

/// A handle to receive the raw bytes read by a `CapturingStream`.
pub struct RawCaptureHandle {
    rx: oneshot::Receiver<CapturedBytes>,
}

/// Raw bytes captured from both directions of a `CapturingStream`.
#[derive(Debug, Default)]
pub struct CapturedBytes {
    /// Bytes read from the inner stream (inbound — server flight).
    pub inbound: Vec<u8>,
    /// Bytes written to the inner stream (outbound — client flight, e.g. ClientHello).
    pub outbound: Vec<u8>,
}

impl RawCaptureHandle {
    /// Collect all captured raw bytes. Waits for the `CapturingStream` to be
    /// dropped (its `AsyncRead`/`AsyncWrite` impls append to internal buffers;
    /// this returns the buffers once the sender side is dropped).
    pub async fn collect(self) -> CapturedBytes {
        self.rx.await.unwrap_or_default()
    }
}

/// Wraps an inner `AsyncRead + AsyncWrite` stream and copies every byte read
/// from and written to it into internal buffers, which are sent to the
/// `RawCaptureHandle` when this struct is dropped. This lets us record the
/// raw TLS record bytes that `tokio-rustls` would otherwise decrypt/discard
/// (inbound) and the ClientHello bytes the client sends (outbound).
struct CapturingStream<S> {
    inner: S,
    /// Inbound bytes (server→client).
    read_buf: Vec<u8>,
    /// Outbound bytes (client→server, e.g. ClientHello).
    write_buf: Vec<u8>,
    tx: Option<oneshot::Sender<CapturedBytes>>,
}

impl<S> Drop for CapturingStream<S> {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(CapturedBytes {
                inbound: std::mem::take(&mut self.read_buf),
                outbound: std::mem::take(&mut self.write_buf),
            });
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CapturingStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                this.read_buf.extend_from_slice(&buf.filled()[before..after]);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CapturingStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            this.write_buf.extend_from_slice(&buf[..*n]);
        }
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Create a `CapturingStream` and return it together with the handle for
/// collecting the captured bytes (both inbound and outbound).
fn capturing_stream<S: AsyncRead + AsyncWrite + Unpin>(
    inner: S,
) -> (CapturingStream<S>, RawCaptureHandle) {
    let (tx, rx) = oneshot::channel();
    let handle = RawCaptureHandle { rx };
    (CapturingStream {
        inner,
        read_buf: Vec::with_capacity(16384),
        write_buf: Vec::with_capacity(4096),
        tx: Some(tx),
    }, handle)
}

// =============================================================================
// Raw TLS flight parser
// =============================================================================

/// Parse a raw TLS 1.3 server flight (sequence of TLS records) and extract:
/// - The ServerHello record (including its TLS record header)
/// - The certificate chain (each certificate as a separate Vec<u8>)
/// - The negotiated TLS version from the ServerHello
///
/// Returns `None` if the flight does not contain a valid ServerHello.
fn parse_raw_tls_flight(raw: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>, u16)> {
    let mut offset = 0usize;
    let mut server_hello: Option<Vec<u8>> = None;
    let mut tls_version: Option<u16> = None;
    let mut certificates: Vec<Vec<u8>> = Vec::new();

    while offset + 5 <= raw.len() {
        let record_type = raw[offset];
        let record_len = u16::from_be_bytes([raw[offset + 3], raw[offset + 4]]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > raw.len() {
            break;
        }
        let record_body = &raw[offset + 5..record_end];

        if record_type == 0x16 {
            // Handshake record — parse handshake messages within.
            let mut hs_off = 0usize;
            while hs_off + 4 <= record_body.len() {
                let hs_type = record_body[hs_off];
                let hs_len = ((record_body[hs_off + 1] as usize) << 16)
                    | ((record_body[hs_off + 2] as usize) << 8)
                    | (record_body[hs_off + 3] as usize);
                let hs_end = hs_off + 4 + hs_len;
                if hs_end > record_body.len() {
                    break;
                }
                let hs_body = &record_body[hs_off + 4..hs_end];

                match hs_type {
                    0x02 => {
                        // ServerHello
                        // The full record (header + body) is stored for replay.
                        server_hello = Some(raw[offset..record_end].to_vec());
                        // legacy_record_version is at raw[offset+1..offset+3]
                        tls_version =
                            Some(u16::from_be_bytes([raw[offset + 1], raw[offset + 2]]));
                    }
                    0x0b => {
                        // Certificate
                        // Parse the certificate list and extract each DER cert.
                        if hs_body.len() >= 3 {
                            let _list_len = ((hs_body[0] as usize) << 16)
                                | ((hs_body[1] as usize) << 8)
                                | (hs_body[2] as usize);
                            let mut cert_off = 3usize;
                            while cert_off + 3 <= hs_body.len() {
                                let cert_len = ((hs_body[cert_off] as usize) << 16)
                                    | ((hs_body[cert_off + 1] as usize) << 8)
                                    | (hs_body[cert_off + 2] as usize);
                                let cert_data_end = cert_off + 3 + cert_len;
                                if cert_data_end > hs_body.len() {
                                    break;
                                }
                                certificates
                                    .push(hs_body[cert_off + 3..cert_data_end].to_vec());
                                cert_off = cert_data_end + 2; // skip 2-byte extensions
                            }
                        }
                    }
                    _ => {}
                }
                hs_off = hs_end;
            }
        }
        offset = record_end;
    }

    let server_hello = server_hello?;
    let version = tls_version.unwrap_or(0x0303);
    Some((server_hello, certificates, version))
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
            raw_flight: vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0c],
            client_hello: vec![],
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
            raw_flight: vec![0x16],
            client_hello: vec![],
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
            raw_flight: vec![],
            client_hello: vec![],
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
    fn parse_raw_tls_flight_extracts_server_hello() {
        // Build a minimal synthetic TLS flight: one Handshake record containing
        // a ServerHello (type 0x02) with a 2-byte body.
        let mut flight = Vec::new();
        flight.push(0x16); // record type: Handshake
        flight.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_record_version
        let sh_body = [0x02u8, 0x00, 0x00, 0x02, 0xAA, 0xBB]; // ServerHello, len=2, payload
        flight.extend_from_slice(&(sh_body.len() as u16).to_be_bytes()); // record length
        flight.extend_from_slice(&sh_body);

        let (server_hello, certs, version) =
            parse_raw_tls_flight(&flight).expect("must parse ServerHello");
        assert_eq!(server_hello, flight, "server_hello should be the full record");
        assert!(certs.is_empty(), "no certificates in this flight");
        assert_eq!(version, 0x0303);
    }

    #[test]
    fn parse_raw_tls_flight_extracts_certificates() {
        // Build a flight with a ServerHello record followed by a Certificate record.
        let mut flight = Vec::new();

        // ServerHello record
        flight.push(0x16);
        flight.extend_from_slice(&0x0303u16.to_be_bytes());
        let sh_hs = [0x02u8, 0x00, 0x00, 0x02, 0xAA, 0xBB];
        flight.extend_from_slice(&(sh_hs.len() as u16).to_be_bytes());
        flight.extend_from_slice(&sh_hs);

        // Certificate record: handshake type 0x0b, 3-byte length, 3-byte list length,
        // then one cert entry (3-byte length + cert data + 2-byte extensions).
        let cert_der = [0x30, 0x82, 0x01, 0x00]; // minimal DER-ish
        let mut cert_entry = Vec::new();
        cert_entry.extend_from_slice(&(cert_der.len() as u32).to_be_bytes()[1..4]); // 3-byte len
        cert_entry.extend_from_slice(&cert_der);
        cert_entry.extend_from_slice(&0u16.to_be_bytes()); // 2-byte extensions

        let mut cert_hs_body = Vec::new();
        let list_len = cert_entry.len();
        cert_hs_body.extend_from_slice(&(list_len as u32).to_be_bytes()[1..4]); // 3-byte list len
        cert_hs_body.extend_from_slice(&cert_entry);

        let mut cert_record = Vec::new();
        cert_record.push(0x0b); // Certificate handshake type
        cert_record.extend_from_slice(&(cert_hs_body.len() as u32).to_be_bytes()[1..4]); // 3-byte hs len
        cert_record.extend_from_slice(&cert_hs_body);

        flight.push(0x16); // record type: Handshake
        flight.extend_from_slice(&0x0303u16.to_be_bytes());
        flight.extend_from_slice(&(cert_record.len() as u16).to_be_bytes());
        flight.extend_from_slice(&cert_record);

        let (_server_hello, certs, _version) =
            parse_raw_tls_flight(&flight).expect("must parse flight");
        assert_eq!(certs.len(), 1, "should extract one certificate");
        assert_eq!(certs[0], cert_der, "cert DER should match");
    }

    #[test]
    fn parse_raw_tls_flight_returns_none_without_server_hello() {
        // A flight with only an ApplicationData record should return None.
        let flight = [0x17u8, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        assert!(parse_raw_tls_flight(&flight).is_none());
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

    /// Regression test for the capture-path deadlock (TODO-415 rework).
    ///
    /// `RawCaptureHandle::collect()` awaits a oneshot receiver that is only
    /// fulfilled when the `CapturingStream` is dropped. If the owner of the
    /// `CapturingStream` is not dropped before `collect()`, the call deadlocks.
    /// This test verifies that dropping the stream releases the captured bytes
    /// and `collect()` returns promptly.
    #[test]
    fn capturing_stream_collect_returns_after_drop() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            // Use an in-memory duplex pipe so we control the "server" side.
            let (mut server, client) = tokio::io::duplex(1024);

            // Write known bytes from the server side before wrapping the client.
            let payload = b"HELLO_CAPTURE_BYTES";
            server.write_all(payload).await.expect("server write");
            // Close the server side so the client read hits EOF.
            drop(server);

            let (mut capturing, handle) = capturing_stream(client);

            // Read everything from the capturing stream to drain it.
            let mut buf = vec![0u8; 256];
            let _ = capturing.read(&mut buf).await;

            // CRITICAL: drop the capturing stream BEFORE collect().
            // This triggers CapturingStream::drop which sends the buffer.
            drop(capturing);

            // collect() must return promptly (not deadlock).
            let captured = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                handle.collect(),
            )
            .await
            .expect("collect() must not deadlock");

            assert!(
                captured.inbound.windows(payload.len()).any(|w| w == payload),
                "captured inbound bytes must contain the payload; got {} bytes: {:?}",
                captured.inbound.len(),
                &captured.inbound[..captured.inbound.len().min(payload.len())]
            );
        });
    }
}
