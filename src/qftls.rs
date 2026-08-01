#![allow(unexpected_cfgs)]
// Unified TLS stack for QuicFuscate
// Consolidates: tls_provider.rs, tls_combined.rs, RealTLS_rustls.rs
// Provides a single public surface: Level, TlsProfile, QuicTlsProvider, create_provider()

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use zeroize::Zeroizing;

use crate::error::ConnectionError;
use crate::transport::packet::CryptoContext;

static TLS_CERT_PATH_OVERRIDE: OnceLock<String> = OnceLock::new();
static TLS_KEY_PATH_OVERRIDE: OnceLock<String> = OnceLock::new();
static TLS_SERVER_IDENTITY_OVERRIDE: OnceLock<PreloadedServerIdentity> = OnceLock::new();
static TLS_CA_PATH_OVERRIDE: OnceLock<String> = OnceLock::new();
static TLS_OVERRIDE_REQUIRED: AtomicBool = AtomicBool::new(false);
/// Configurable max early data size for server TLS config.
/// RFC 9001 §4.6.1: QUIC requires this to be either 0 (no 0-RTT) or 0xFFFF_FFFF (0-RTT enabled).
/// Default is u32::MAX (0-RTT offered). Set to 0 to disable 0-RTT.
/// Set via `set_max_early_data_size()` before server connection creation.
static MAX_EARLY_DATA_SIZE: AtomicU32 = AtomicU32::new(u32::MAX);

struct PreloadedServerIdentity {
    cert_pem: Vec<u8>,
    key_pem: Zeroizing<Vec<u8>>,
}

/// Set the maximum early data size for new server TLS connections.
pub fn set_max_early_data_size(size: u32) {
    MAX_EARLY_DATA_SIZE.store(size, Ordering::Relaxed);
}
const DEFAULT_TLS_SNI_HOST: &str = "cdn.cloudflare.com";

fn trace_key_change(is_server: bool, label: &str) {
    log::trace!("[qftls] {:?} keychange={}", if is_server { "server" } else { "client" }, label);
}

fn trace_hp_error(message: &str) {
    log::trace!("[qftls] {}", message);
}

fn trace_hp_mask(mask0: u8, pn: [u8; 4]) {
    log::trace!(
        "[qftls] hp mask0={:02x} pn={:02x}{:02x}{:02x}{:02x}",
        mask0,
        pn[0],
        pn[1],
        pn[2],
        pn[3]
    );
}

/// Override the TLS certificate and private key file paths for server mode.
pub fn set_tls_cert_key_paths(cert_path: &str, key_path: &str) {
    if TLS_CERT_PATH_OVERRIDE.set(cert_path.to_string()).is_err() {
        log::debug!("TLS cert path override already set, keeping existing value");
    }
    if TLS_KEY_PATH_OVERRIDE.set(key_path.to_string()).is_err() {
        log::debug!("TLS key path override already set, keeping existing value");
    }
    TLS_OVERRIDE_REQUIRED.store(true, Ordering::SeqCst);
}

/// Read and validate the server identity before privileged initialization ends.
///
/// New server connections use this in-memory copy instead of reopening a
/// root-owned private-key file after the process drops to its runtime UID.
pub fn preload_tls_server_identity(cert_path: &str, key_path: &str) -> Result<(), ConnectionError> {
    let cert_pem = std::fs::read(cert_path).map_err(|error| {
        ConnectionError::TlsError(format!("Cert read failed ({cert_path}): {error}"))
    })?;
    let key_pem = Zeroizing::new(std::fs::read(key_path).map_err(|error| {
        ConnectionError::TlsError(format!("Key read failed ({key_path}): {error}"))
    })?);
    rustls_provider::validate_server_identity_pem(&cert_pem, key_pem.as_slice())?;

    #[cfg(unix)]
    if unsafe { libc::mlock(key_pem.as_ptr().cast(), key_pem.len()) } != 0 {
        log::warn!(
            "Failed to lock preloaded TLS private key in memory: {}",
            std::io::Error::last_os_error()
        );
    }

    if TLS_SERVER_IDENTITY_OVERRIDE.set(PreloadedServerIdentity { cert_pem, key_pem }).is_err() {
        log::debug!("TLS server identity already preloaded, keeping existing value");
    }
    set_tls_cert_key_paths(cert_path, key_path);
    Ok(())
}

/// Override the TLS CA file path for client mode peer verification.
/// When set, the CA file is loaded and added to the root certificate store
/// in addition to native/webpki roots.
pub fn set_tls_ca_path(ca_path: &str) {
    if TLS_CA_PATH_OVERRIDE.set(ca_path.to_string()).is_err() {
        log::debug!("TLS CA path override already set, keeping existing value");
    }
}

// ===============================
// Core Types and Trait
// ===============================

/// QUIC encryption levels
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Initial encryption level (connection establishment).
    Initial = 0,
    /// 0-RTT early data encryption level.
    EarlyData = 1,
    /// Handshake encryption level (during TLS negotiation).
    Handshake = 2,
    /// Application data encryption level (post-handshake).
    Application = 3,
}

/// TLS Profile for stealth configuration
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Human-readable browser user-agent string (e.g., "Chrome/136.0.0.0").
    pub name: String,
    /// TLS cipher suite IDs in preference order.
    pub cipher_suites: Vec<u16>,
    /// Supported named groups (key exchange curves) in preference order.
    pub groups: Vec<u16>,
    /// Supported signature algorithms in preference order.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol identifiers (e.g., ["h3", "h2"]).
    pub alpn_protocols: Vec<String>,
    /// SNI hostname override (None uses connection default).
    pub sni: Option<String>,
    /// Enable 0-RTT early data in this profile.
    pub enable_0rtt: bool,
    /// Enable Encrypted Client Hello (ECH) extension.
    pub enable_ech: bool,
    /// GREASE values to inject for fingerprint realism.
    pub grease_values: Vec<u16>,
    /// ClientHello extension ordering to match browser fingerprint.
    pub extension_order: Vec<u16>,
    /// Optional cosmetic timing jitter for fingerprint realism.
    pub timing_jitter: Option<std::time::Duration>,
    /// If true, TLS Cover runs without artificial delays.
    pub cover_performance_mode: bool,
}

impl TlsProfile {
    /// Chrome 136 Profile - Most common browser
    pub fn chrome_130() -> Self {
        Self {
            name: "Chrome/136.0.0.0".into(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        // ChaCha suites removed per policy
            ],
            groups: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x001e, // x448
            ],
            signature_algorithms: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0603, // ecdsa_secp521r1_sha512
                0x0807, // ed25519
                0x0808, // ed448
                0x0804, // rsa_pss_rsae_sha256
                0x0805, // rsa_pss_rsae_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0401, // rsa_pkcs1_sha256
                0x0501, // rsa_pkcs1_sha384
            ],
            alpn_protocols: vec!["h3".into(), "h2".into(), "http/1.1".into()],
            sni: None,
            enable_0rtt: true,
            enable_ech: true,
            grease_values: vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a],
            extension_order: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0x0000, // renegotiation_info
                0x000d, // supported_groups
                0xfe0d, // encrypted_client_hello
                0x0023, // session_ticket
                0x0019, // compress_certificate
                0x0010, // application_layer_protocol_negotiation
                0x002d, // psk_key_exchange_modes
                0x0033, // key_share
                0x002b, // supported_versions
                0x001b, // compress_certificate
                0x0039, // quic_transport_parameters
                0x0a0a, // GREASE
                0x0029, // pre_shared_key (must be last)
            ],
            // Non-security jitter: rand::random is fine here; this is cosmetic timing
            // variation for TLS fingerprint realism, not a cryptographic secret.
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 50)),
            cover_performance_mode: false,
        }
    }

    /// Firefox 138 Profile
    pub fn firefox_133() -> Self {
        Self {
            name: "Firefox/138.0".into(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                        // ChaCha suites removed per policy
            ],
            groups: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
                0x0019, // secp521r1
                0x0100, // ffdhe2048
                0x0101, // ffdhe3072
            ],
            signature_algorithms: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0603, // ecdsa_secp521r1_sha512
                0x0807, // ed25519
                0x0808, // ed448
                0x0804, // rsa_pss_rsae_sha256
                0x0805, // rsa_pss_rsae_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0401, // rsa_pkcs1_sha256
            ],
            alpn_protocols: vec!["h3".into(), "h2".into(), "http/1.1".into()],
            sni: None,
            enable_0rtt: true,
            enable_ech: false, // Firefox doesn't enable ECH by default yet
            grease_values: vec![],
            extension_order: vec![
                0x0000, // server_name
                0x0023, // session_ticket
                0x000d, // supported_groups
                0x000a, // supported_curves (legacy)
                0x0010, // application_layer_protocol_negotiation
                0x002d, // psk_key_exchange_modes
                0x0033, // key_share
                0x002b, // supported_versions
                0x001c, // record_size_limit
                0x0039, // quic_transport_parameters
            ],
            // Non-security jitter: cosmetic timing variation for fingerprint realism.
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 30)),
            cover_performance_mode: false,
        }
    }

    /// Safari 18.3 Profile
    pub fn safari_18() -> Self {
        Self {
            name: "Safari/18.3".into(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        // ChaCha suites removed per policy
            ],
            groups: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ],
            signature_algorithms: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0807, // ed25519
                0x0804, // rsa_pss_rsae_sha256
                0x0805, // rsa_pss_rsae_sha384
                0x0401, // rsa_pkcs1_sha256
            ],
            alpn_protocols: vec!["h3".into(), "h2".into()],
            sni: None,
            enable_0rtt: true,
            enable_ech: false,
            grease_values: vec![],
            extension_order: vec![
                0x0000, // server_name
                0x000d, // supported_groups
                0x0010, // application_layer_protocol_negotiation
                0x0033, // key_share
                0x002b, // supported_versions
                0x0023, // session_ticket
                0x002d, // psk_key_exchange_modes
                0x0039, // quic_transport_parameters
            ],
            // Non-security jitter: cosmetic timing variation for fingerprint realism.
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 20)),
            cover_performance_mode: false,
        }
    }

    /// Edge 130 (Chrome-based)
    pub fn edge_130() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Edge/130.0.0.0".into();
        profile
    }

    /// Opera 115 (Chrome-based with tweaks)
    pub fn opera_115() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Opera/115.0.0.0".into();
        // Opera adds some custom extensions
        profile.extension_order.insert(5, 0x5500); // Opera custom
        profile
    }

    /// Brave 1.73 (Chrome-based, privacy-focused)
    pub fn brave_1_73() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Brave/1.73.0".into();
        profile.enable_ech = false; // Brave profile keeps ECH disabled.
        profile.grease_values.clear(); // Less GREASE
        profile
    }

    /// Rotate between profiles randomly.
    ///
    /// Uses rand::random for non-security profile selection (stealth heuristic,
    /// not a cryptographic decision).
    pub fn random() -> Self {
        use rand::Rng;
        match rand::rng().random_range(0..6u8) {
            0 => Self::chrome_130(),
            1 => Self::firefox_133(),
            2 => Self::safari_18(),
            3 => Self::edge_130(),
            4 => Self::opera_115(),
            _ => Self::brave_1_73(),
        }
    }
}

/// Build a TlsProfile from a Stealth FingerprintProfile (best-effort mapping).
pub fn profile_from_fingerprint(fp: &crate::stealth::FingerprintProfile) -> TlsProfile {
    use crate::stealth::BrowserProfile as B;
    let mut p = match fp.browser {
        B::Chrome => TlsProfile::chrome_130(),
        B::Firefox => TlsProfile::firefox_133(),
        B::Safari => TlsProfile::safari_18(),
        B::Edge => TlsProfile::edge_130(),
    };
    // Apply cipher suite preference from fingerprint when available
    if !fp.tls_cipher_suites.is_empty() {
        p.cipher_suites = fp.tls_cipher_suites.clone();
    }
    // Prefer HTTP/3 first
    p.alpn_protocols = vec!["h3".into(), "h2".into(), "http/1.1".into()];
    // Enforce policy: remove ChaCha suites and prefer AES-GCM
    p.cipher_suites.retain(|cs| *cs != 0x1303 && *cs != 0xCCA8 && *cs != 0xCCA9);
    p.cipher_suites.sort_by_key(|cs| match *cs {
        0x1301 | 0x1302 => 0,                   // TLS 1.3 AES-GCM first
        0xC02B | 0xC02F | 0xC02C | 0xC030 => 1, // TLS 1.2 AES-GCM
        _ => 2,
    });
    // Keep ECH preference per browser profile
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_from_fp_has_h3_first() {
        let fp = crate::stealth::FingerprintProfile::new(
            crate::stealth::BrowserProfile::Chrome,
            crate::stealth::OsProfile::Windows,
        );
        let p = profile_from_fingerprint(&fp);
        assert!(!p.alpn_protocols.is_empty());
        assert_eq!(p.alpn_protocols[0], "h3");
        assert!(!p.cipher_suites.is_empty());
    }

    #[test]
    fn v2_provider_carries_version_information_transport_parameter() {
        let crypto = Arc::new(RwLock::new(CryptoContext::default()));
        let information = crate::transport::version::VersionInformation {
            chosen: crate::transport::PROTOCOL_VERSION_V2,
            available: vec![
                crate::transport::PROTOCOL_VERSION_V2,
                crate::transport::PROTOCOL_VERSION,
            ],
        }
        .encode_parameter()
        .unwrap();
        let provider = create_provider_for_version(
            false,
            crypto,
            false,
            crate::transport::PROTOCOL_VERSION_V2,
            &information,
        )
        .expect("create v2 provider");
        assert!(provider.get_quic_transport_params().ends_with(&information));
    }

    #[test]
    fn profile_from_fp_is_deterministic_for_same_input() {
        let fp = crate::stealth::FingerprintProfile::new(
            crate::stealth::BrowserProfile::Firefox,
            crate::stealth::OsProfile::Linux,
        );
        let p1 = profile_from_fingerprint(&fp);
        let p2 = profile_from_fingerprint(&fp);
        assert_eq!(p1.name, p2.name);
        assert_eq!(p1.cipher_suites, p2.cipher_suites);
        assert_eq!(p1.groups, p2.groups);
        assert_eq!(p1.extension_order, p2.extension_order);
        assert_eq!(p1.alpn_protocols, p2.alpn_protocols);
    }

    #[test]
    fn profile_from_fp_enforces_tls_policy_constraints() {
        let fps = [
            crate::stealth::FingerprintProfile::new(
                crate::stealth::BrowserProfile::Chrome,
                crate::stealth::OsProfile::Windows,
            ),
            crate::stealth::FingerprintProfile::new(
                crate::stealth::BrowserProfile::Firefox,
                crate::stealth::OsProfile::Linux,
            ),
            crate::stealth::FingerprintProfile::new(
                crate::stealth::BrowserProfile::Safari,
                crate::stealth::OsProfile::MacOS,
            ),
            crate::stealth::FingerprintProfile::new(
                crate::stealth::BrowserProfile::Edge,
                crate::stealth::OsProfile::Windows,
            ),
        ];

        for fp in fps {
            let p = profile_from_fingerprint(&fp);
            assert_eq!(p.alpn_protocols.first().map(String::as_str), Some("h3"));
            assert!(
                !p.cipher_suites.iter().any(|cs| matches!(*cs, 0x1303 | 0xCCA8 | 0xCCA9)),
                "ChaCha suites must be removed by policy for profile {}",
                p.name
            );
        }
    }

    #[test]
    fn profile_chlo_extension_order_keeps_psk_last_when_present() {
        let profiles = [
            TlsProfile::chrome_130(),
            TlsProfile::firefox_133(),
            TlsProfile::safari_18(),
            TlsProfile::edge_130(),
        ];
        for p in profiles {
            let psk_idx = p.extension_order.iter().position(|e| *e == 0x0029);
            if let Some(idx) = psk_idx {
                assert_eq!(
                    idx,
                    p.extension_order.len() - 1,
                    "pre_shared_key extension must remain last for {}",
                    p.name
                );
            }
        }
    }

    #[test]
    fn profile_from_fingerprint_maps_browser_semantics() {
        let chrome = profile_from_fingerprint(&crate::stealth::FingerprintProfile::new(
            crate::stealth::BrowserProfile::Chrome,
            crate::stealth::OsProfile::Windows,
        ));
        let firefox = profile_from_fingerprint(&crate::stealth::FingerprintProfile::new(
            crate::stealth::BrowserProfile::Firefox,
            crate::stealth::OsProfile::Linux,
        ));
        let safari = profile_from_fingerprint(&crate::stealth::FingerprintProfile::new(
            crate::stealth::BrowserProfile::Safari,
            crate::stealth::OsProfile::MacOS,
        ));
        let edge = profile_from_fingerprint(&crate::stealth::FingerprintProfile::new(
            crate::stealth::BrowserProfile::Edge,
            crate::stealth::OsProfile::Windows,
        ));

        assert!(chrome.name.contains("Chrome"));
        assert!(firefox.name.contains("Firefox"));
        assert!(safari.name.contains("Safari"));
        assert!(edge.name.contains("Edge"));
    }

    #[test]
    fn tls_provider_defaults_to_rustls_owner() {
        let crypto = Arc::new(RwLock::new(crate::transport::packet::CryptoContext::default()));
        let provider = create_provider(false, crypto).unwrap();

        assert!(provider.provider_name().starts_with("rustls"));
    }

    #[test]
    fn tls_cover_support_matches_provider_name() {
        let cover_enabled = std::env::var("QUICFUSCATE_TLS_COVER")
            .map(|raw| raw != "0" && !raw.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        let crypto = Arc::new(RwLock::new(crate::transport::packet::CryptoContext::default()));
        let provider = create_provider(false, crypto).unwrap();

        assert_eq!(provider.supports_ch_override(), cover_enabled);
        assert_eq!(provider.provider_name() == "rustls+tls-cover", cover_enabled);
    }

    #[test]
    fn test_profile_chrome_has_h3_alpn() {
        let p = TlsProfile::chrome_130();
        assert!(
            p.alpn_protocols.iter().any(|a| a == "h3"),
            "Chrome profile must include h3 in ALPN"
        );
    }

    #[test]
    fn test_profile_firefox_has_h3_alpn() {
        let p = TlsProfile::firefox_133();
        assert!(
            p.alpn_protocols.iter().any(|a| a == "h3"),
            "Firefox profile must include h3 in ALPN"
        );
    }

    #[test]
    fn test_profile_safari_has_h3_alpn() {
        let p = TlsProfile::safari_18();
        assert!(
            p.alpn_protocols.iter().any(|a| a == "h3"),
            "Safari profile must include h3 in ALPN"
        );
    }

    #[test]
    fn test_profile_brave_disables_ech() {
        let p = TlsProfile::brave_1_73();
        assert!(!p.enable_ech, "Brave profile must have ECH disabled");
    }

    #[test]
    fn test_profile_random_produces_valid_profile() {
        // Call random() multiple times to cover different branches
        for _ in 0..20 {
            let p = TlsProfile::random();
            assert!(!p.name.is_empty(), "random profile must have a name");
            assert!(
                !p.extension_order.is_empty(),
                "random profile must have non-empty extensions for {}",
                p.name
            );
            assert!(
                !p.cipher_suites.is_empty(),
                "random profile must have cipher suites for {}",
                p.name
            );
            assert!(
                !p.alpn_protocols.is_empty(),
                "random profile must have ALPN protocols for {}",
                p.name
            );
        }
    }

    #[test]
    fn test_all_browser_profiles_have_cipher_suites() {
        let profiles = [
            TlsProfile::chrome_130(),
            TlsProfile::firefox_133(),
            TlsProfile::safari_18(),
            TlsProfile::edge_130(),
            TlsProfile::opera_115(),
            TlsProfile::brave_1_73(),
        ];
        for p in &profiles {
            assert!(
                !p.cipher_suites.is_empty(),
                "profile {} must have non-empty cipher_suites",
                p.name
            );
            // All TLS 1.3 profiles should contain at least one TLS 1.3 cipher
            assert!(
                p.cipher_suites.iter().any(|cs| *cs == 0x1301 || *cs == 0x1302),
                "profile {} must contain at least one TLS 1.3 AES-GCM cipher suite",
                p.name
            );
        }
    }
}

/// TLS Provider abstraction used by transport.
///
/// The actual protocol TLS engine is always rustls.
/// Optional TLS cover behavior is composed on top of it.
pub trait QuicTlsProvider: Send + Sync {
    /// Configure with profile
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError>;
    /// Set server name for SNI
    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError>;
    /// Provide incoming CRYPTO frame data
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError>;
    /// Get next outgoing CRYPTO frame
    fn next_crypto_frame(&mut self, level: Level, max_len: usize) -> Option<(u64, Vec<u8>)>;
    /// Poll for new secrets and install them
    fn poll_secrets_and_install(
        &mut self,
        crypto: &Arc<RwLock<CryptoContext>>,
    ) -> Result<(), ConnectionError>;
    /// Check if handshake is complete
    fn handshake_complete(&self) -> bool;
    /// Get negotiated ALPN protocol
    fn alpn(&self) -> Option<&str>;
    /// Get peer certificate (if any)
    fn peer_cert(&self) -> Option<Vec<u8>>;
    /// Get peer certificate chain (if any) - full chain DER encoded
    fn peer_cert_chain(&self) -> Option<Vec<Vec<u8>>> {
        // Default: return just the leaf cert if available
        self.peer_cert().map(|c| vec![c])
    }
    /// Get configured server name (SNI)
    fn server_name_get(&self) -> Option<&str>;
    /// Get TLS session ticket for resumption (if any)
    fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>>;
    /// Enable 0-RTT if supported
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError>;
    /// Get 0-RTT keys if available
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)>;
    /// Export keying material (for QUIC key update)
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, ConnectionError>;
    /// Get transport parameters to send
    fn get_quic_transport_params(&self) -> Vec<u8>;
    /// Set peer's transport parameters
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError>;
    /// Returns authenticated peer transport parameters once rustls exposes them.
    fn peer_quic_transport_params(&self) -> Option<Vec<u8>>;
    /// Initiate key update
    fn key_update(&mut self) -> Result<(), ConnectionError>;
    /// Advance read-side 1-RTT keys only.
    fn key_update_read(&mut self) -> Result<(), ConnectionError> {
        self.key_update()
    }
    /// Advance write-side 1-RTT keys only.
    fn key_update_write(&mut self) -> Result<(), ConnectionError> {
        self.key_update()
    }
    /// Get provider name (for debugging)
    fn provider_name(&self) -> &str;
    /// Check if provider supports ClientHello override through cover/mimicry layer.
    fn supports_ch_override(&self) -> bool;
    /// Apply ClientHello override (if supported)
    fn apply_ch_override(&mut self, _template: &[u8]) -> Result<(), ConnectionError> {
        if !self.supports_ch_override() {
            return Err(ConnectionError::TlsError("Provider doesn't support CH override".into()));
        }
        Ok(())
    }
}

/// Create the canonical TLS provider.
///
/// This always returns the real rustls transport owner with optional cover-layer composition.
pub fn create_provider(
    is_server: bool,
    crypto: Arc<RwLock<CryptoContext>>,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_with_peer_verification(is_server, crypto, true)
}

pub(crate) fn create_provider_with_peer_verification(
    is_server: bool,
    crypto: Arc<RwLock<CryptoContext>>,
    verify_peer: bool,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_for_version(
        is_server,
        crypto,
        verify_peer,
        crate::transport::PROTOCOL_VERSION,
        &[],
    )
}

pub(crate) fn create_provider_for_version(
    is_server: bool,
    crypto: Arc<RwLock<CryptoContext>>,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    Ok(Box::new(CombinedProvider::new(
        is_server,
        crypto,
        verify_peer,
        version,
        version_information_parameter,
    )?))
}

// ===============================
// Combined Provider (rustls + optional TLS Cover)
// rustls remains the TLS protocol owner; cover is an overlay only.
// ===============================

/// Combined TLS provider composing rustls (protocol owner) with an optional TLS cover overlay.
pub struct CombinedProvider {
    rustls: RustlsProvider,
    cover: Option<crate::stealth::TlsCoverProvider>,
}

impl CombinedProvider {
    fn env_string(name: &str, default: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| default.to_string())
    }

    /// Create a new combined provider (rustls + optional TLS cover).
    pub fn new(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
    ) -> Result<Self, ConnectionError> {
        let rustls = RustlsProvider::new(
            is_server,
            crypto.clone(),
            verify_peer,
            version,
            version_information_parameter,
        )?;
        // Cover is optional and intentionally separated from TLS protocol semantics.
        // It can be disabled via ENV QUICFUSCATE_TLS_COVER=0.
        // In base/performance mode, cover keeps traffic shape with reduced timing overhead.
        let cover_enabled = crate::env_utils::env_flag("QUICFUSCATE_TLS_COVER", true);
        let cover = if cover_enabled {
            // Check stealth mode to determine TLS Cover behavior
            let stealth_mode = Self::env_string("QUICFUSCATE_STEALTH_MODE", "stealth");

            let mut tls_cover = crate::stealth::TlsCoverProvider::new(is_server, crypto.clone())?;

            // In base/performance mode, TLS Cover still runs but without artificial delays
            if stealth_mode == "base" || stealth_mode == "performance" || stealth_mode == "off" {
                tls_cover.set_performance_mode(true);
                log::info!("TLS Cover enabled in performance mode: full cover traffic, no delays");
            } else {
                log::info!(
                    "TLS Cover enabled in stealth mode: full sophistication with timing/padding"
                );
            }

            // Enable profile rotation if requested
            if crate::env_utils::env_flag("QUICFUSCATE_TLS_COVER_ROTATE", false) {
                log::info!("TLS Cover profile rotation enabled");
            }

            // Enable telemetry if requested
            if crate::env_utils::env_flag("QUICFUSCATE_TLS_COVER_TELEMETRY", false) {
                log::info!("TLS Cover telemetry enabled");
            }

            Some(tls_cover)
        } else {
            None
        };
        // Telemetry: 0 = rustls-only, 1 = rustls+tls-cover
        let kind = if cover.is_some() { 1 } else { 0 };
        crate::optimize::telemetry::TLS_PROVIDER_KIND.set(kind);
        Ok(Self { rustls, cover })
    }
}

impl QuicTlsProvider for CombinedProvider {
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
        // Configure rustls first (protocol semantics).
        self.rustls.configure(profile)?;
        // Apply session hint (ALPN/SNI bias) if available.
        self.rustls.apply_session_hint_to_profile();
        // Apply optional cover layer configuration.
        if let Some(ref mut c) = self.cover {
            c.set_performance_mode(profile.cover_performance_mode);
            c.apply_ch_override(&[])?; /* no-op template seed */
        }
        Ok(())
    }

    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError> {
        self.rustls.set_server_name(name)?;
        Ok(())
    }

    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError> {
        if let Some(ref mut c) = self.cover {
            if let Err(e) = c.provide_quic_data(level, data) {
                log::debug!("TLS cover provider rejected QUIC data at level {:?}: {}", level, e);
            }
        }
        self.rustls.provide_quic_data(level, data)
    }

    fn next_crypto_frame(&mut self, level: Level, max_len: usize) -> Option<(u64, Vec<u8>)> {
        // rustls-driven handshake frames always take priority.
        if let Some(frame) = self.rustls.next_crypto_frame(level, max_len) {
            return Some(frame);
        }
        // Emit optional cover decoy frames before real handshake completion.
        if let Some(ref mut c) = self.cover {
            if !self.rustls.handshake_complete() {
                return c.next_crypto_frame(level, max_len);
            }
        }
        None
    }

    fn poll_secrets_and_install(
        &mut self,
        crypto: &Arc<RwLock<CryptoContext>>,
    ) -> Result<(), ConnectionError> {
        if let Some(ref mut c) = self.cover {
            if let Err(e) = c.poll_secrets_and_install(crypto) {
                log::debug!("TLS cover provider secret poll/install failed: {}", e);
            }
        }
        self.rustls.poll_secrets_and_install(crypto)
    }

    fn handshake_complete(&self) -> bool {
        self.rustls.handshake_complete()
    }
    fn alpn(&self) -> Option<&str> {
        self.rustls.alpn()
    }
    fn peer_cert(&self) -> Option<Vec<u8>> {
        self.rustls.peer_cert()
    }
    fn server_name_get(&self) -> Option<&str> {
        self.rustls.server_name_get()
    }
    fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.rustls.session_ticket()
    }
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError> {
        self.rustls.enable_0rtt()
    }
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.rustls.get_0rtt_keys()
    }
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, ConnectionError> {
        self.rustls.export_keying_material(label, context, length)
    }
    fn get_quic_transport_params(&self) -> Vec<u8> {
        self.rustls.get_quic_transport_params()
    }
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError> {
        self.rustls.set_peer_transport_params(params)
    }
    fn peer_quic_transport_params(&self) -> Option<Vec<u8>> {
        self.rustls.peer_quic_transport_params()
    }
    fn key_update(&mut self) -> Result<(), ConnectionError> {
        self.rustls.key_update()
    }
    fn key_update_read(&mut self) -> Result<(), ConnectionError> {
        self.rustls.key_update_read()
    }
    fn key_update_write(&mut self) -> Result<(), ConnectionError> {
        self.rustls.key_update_write()
    }
    fn provider_name(&self) -> &str {
        if self.cover.is_some() {
            "rustls+tls-cover"
        } else {
            "rustls"
        }
    }
    fn supports_ch_override(&self) -> bool {
        self.cover.is_some()
    }
    fn apply_ch_override(&mut self, template: &[u8]) -> Result<(), ConnectionError> {
        if let Some(ref mut c) = self.cover {
            c.apply_ch_override(template)
        } else {
            Err(ConnectionError::TlsError("Cover not enabled".into()))
        }
    }
}

// ===============================
// Native rustls 0.23 QUIC provider
// ===============================

mod rustls_provider {
    use super::*;
    use parking_lot::RwLock;
    #[cfg(debug_assertions)]
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    #[cfg(debug_assertions)]
    use rustls::pki_types::UnixTime;
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
    #[cfg(debug_assertions)]
    use rustls::DigitallySignedStruct;
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_native_certs::load_native_certs;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use webpki_roots;

    pub(super) fn validate_server_identity_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<(), ConnectionError> {
        let certs =
            CertificateDer::pem_slice_iter(cert_pem).collect::<Result<Vec<_>, _>>().map_err(
                |error| ConnectionError::TlsError(format!("Certificate parse failed: {error}")),
            )?;
        if certs.is_empty() {
            return Err(ConnectionError::TlsError(
                "Certificate chain must not be empty".to_string(),
            ));
        }
        PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|error| ConnectionError::TlsError(format!("Key parse failed: {error}")))?;
        Ok(())
    }

    /// Full-featured rustls QUIC TLS provider with session resumption, 0-RTT, and PQ support.
    pub struct RustlsProviderImpl {
        /// Active rustls QUIC connection (client or server side).
        pub connection: rustls::quic::Connection,
        /// Shared crypto context for installing packet protection keys.
        pub crypto: Arc<RwLock<CryptoContext>>,
        /// True if this is a server-side provider.
        pub is_server: bool,
        /// Whether the client verifies the server certificate.
        #[cfg(debug_assertions)]
        pub verify_peer: bool,
        /// Whether the TLS handshake has completed.
        pub handshake_complete: bool,
        /// Current write-side encryption level.
        pub write_level: super::Level,
        /// Negotiated ALPN protocol string.
        pub alpn: Option<String>,
        /// DER-encoded peer certificate (if verified).
        pub peer_cert: Option<Vec<u8>>,
        /// Whether 0-RTT early data is enabled.
        pub zero_rtt_enabled: bool,
        /// QUIC transport parameters to send to the peer.
        pub transport_params: Vec<u8>,
        /// QUIC wire version used by rustls for TLS-derived packet protection.
        pub quic_version: rustls::quic::Version,
        /// Peer's QUIC transport parameters (received during handshake).
        pub peer_transport_params: Option<Vec<u8>>,
        /// Active TLS profile configuration.
        pub profile: Option<TlsProfile>,
        /// Next 1-RTT secrets for key update.
        pub next_1rtt_secrets: Option<rustls::quic::Secrets>,
        /// Pending local 1-RTT packet keys queued during key update.
        pub pending_local_1rtt: VecDeque<std::sync::Arc<dyn rustls::quic::PacketKey>>,
        /// Pending remote 1-RTT packet keys queued during key update.
        pub pending_remote_1rtt: VecDeque<std::sync::Arc<dyn rustls::quic::PacketKey>>,

        /// Reusable buffer for CRYPTO frame serialization.
        pub crypto_buffer: Vec<u8>,
        /// Queued CRYPTO frames awaiting transmission.
        pub frame_buffer: Vec<(Level, Vec<u8>)>,

        /// TLS session cache for 0-RTT resumption.
        pub session_cache: Option<Arc<RwLock<SessionCache>>>,

        /// Timestamp when the handshake started (for latency measurement).
        pub handshake_start: std::time::Instant,
        /// Total CRYPTO bytes sent.
        pub bytes_sent: usize,
        /// Total CRYPTO bytes received.
        pub bytes_received: usize,
    }

    /// LRU session cache for TLS 0-RTT resumption tickets.
    pub struct SessionCache {
        sessions: std::collections::HashMap<String, SessionData>,
        max_size: usize,
    }

    struct SessionData {
        ticket: crate::secret::SecretBytes,
        master_secret: crate::secret::SecretBytes,
        alpn: String,
        timestamp: std::time::Instant,
    }

    impl SessionCache {
        fn new(max_size: usize) -> Self {
            Self { sessions: Default::default(), max_size }
        }
        fn store(&mut self, server_name: String, data: SessionData) {
            if self.sessions.len() >= self.max_size {
                // LRU eviction
                if let Some(oldest) =
                    self.sessions.iter().min_by_key(|(_, v)| v.timestamp).map(|(k, _)| k.clone())
                {
                    self.sessions.remove(&oldest);
                }
            }
            self.sessions.insert(server_name, data);
        }
        fn get_ticket(&self, server_name: &str) -> Option<Zeroizing<Vec<u8>>> {
            self.sessions
                .get(server_name)
                .map(|data| Zeroizing::new(data.ticket.as_slice().to_vec()))
        }
    }

    #[cfg(test)]
    mod session_secret_tests {
        use super::{SessionCache, SessionData};
        use std::sync::{Arc, Mutex};

        fn session_data(fill: u8) -> SessionData {
            SessionData {
                ticket: crate::secret::SecretBytes::new(vec![fill; 32], "tls_session_ticket"),
                master_secret: crate::secret::SecretBytes::new(
                    vec![fill.wrapping_add(1); 32],
                    "tls_session_master_secret",
                ),
                alpn: "h3".to_string(),
                timestamp: std::time::Instant::now(),
            }
        }

        #[test]
        fn session_cache_eviction_and_drop_erase_retained_secret_material() {
            let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
            let observed = Arc::clone(&events);
            let _observer =
                crate::secret::test_observation::install(Arc::new(move |label, bytes| {
                    observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
                }));

            let mut cache = SessionCache::new(1);
            cache.store("first.example".to_string(), session_data(0x31));
            cache.store("second.example".to_string(), session_data(0x42));
            drop(cache);

            let events = events.lock().expect("erasure events");
            for label in ["tls_session_ticket", "tls_session_master_secret"] {
                let matching = events
                    .iter()
                    .filter(|(event_label, _)| *event_label == label)
                    .collect::<Vec<_>>();
                assert_eq!(matching.len(), 2, "evicted and retained owners must erase for {label}");
                for (_, bytes) in matching {
                    assert_eq!(bytes.len(), 32);
                    assert!(bytes.iter().all(|byte| *byte == 0));
                }
            }
        }
    }

    /// Insecure verifier used only when explicitly requested via env.
    /// Only available in debug builds to prevent accidental production use.
    #[cfg(debug_assertions)]
    #[derive(Debug)]
    struct InsecureAcceptAllVerifier;

    #[cfg(debug_assertions)]
    impl ServerCertVerifier for InsecureAcceptAllVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    impl RustlsProviderImpl {
        /// Create a new rustls QUIC provider for client or server mode.
        pub fn new(
            is_server: bool,
            crypto: Arc<RwLock<CryptoContext>>,
            verify_peer: bool,
            version: u32,
            version_information_parameter: &[u8],
        ) -> Result<Self, ConnectionError> {
            let quic_version = Self::map_quic_version(version)?;
            let mut transport_params = Self::default_transport_params();
            transport_params.extend_from_slice(version_information_parameter);
            let connection = if is_server {
                Self::create_server_connection(quic_version, transport_params.clone())?
            } else {
                Self::create_client_connection(verify_peer, quic_version, transport_params.clone())?
            };
            let this = Self {
                connection,
                crypto,
                is_server,
                #[cfg(debug_assertions)]
                verify_peer,
                handshake_complete: false,
                write_level: super::Level::Initial,
                alpn: None,
                peer_cert: None,
                zero_rtt_enabled: false,
                transport_params,
                quic_version,
                peer_transport_params: None,
                profile: None,
                next_1rtt_secrets: None,
                pending_local_1rtt: VecDeque::new(),
                pending_remote_1rtt: VecDeque::new(),
                crypto_buffer: Vec::with_capacity(4096),
                frame_buffer: Vec::new(),
                session_cache: Some(Arc::new(RwLock::new(SessionCache::new(100)))),
                handshake_start: std::time::Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
            };

            Ok(this)
        }

        fn map_quic_version(version: u32) -> Result<rustls::quic::Version, ConnectionError> {
            match version {
                crate::transport::PROTOCOL_VERSION => Ok(rustls::quic::Version::V1),
                crate::transport::PROTOCOL_VERSION_V2 => Ok(rustls::quic::Version::V2),
                _ => Err(ConnectionError::VersionMismatch),
            }
        }

        fn queue_crypto_bytes(&mut self, level: super::Level, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            let mut crypto = self.crypto.write();
            match level {
                super::Level::Initial => crypto.crypto_initial.send(data),
                super::Level::Handshake => crypto.crypto_handshake.send(data),
                _ => crypto.crypto_application.send(data),
            }
            self.bytes_sent = self.bytes_sent.saturating_add(data.len());
        }

        fn install_key_change(
            &mut self,
            kc: rustls::quic::KeyChange,
        ) -> Result<(), ConnectionError> {
            match kc {
                rustls::quic::KeyChange::Handshake { keys } => {
                    super::trace_key_change(self.is_server, "Handshake");
                    self.install_handshake_keys(keys)?;
                    self.write_level = super::Level::Handshake;
                }
                rustls::quic::KeyChange::OneRtt { keys, next } => {
                    super::trace_key_change(self.is_server, "OneRtt");
                    self.install_1rtt_keys(keys)?;
                    self.next_1rtt_secrets = Some(next);
                    self.write_level = super::Level::Application;
                }
            }
            Ok(())
        }

        fn flush_handshake_io(&mut self) -> Result<(), ConnectionError> {
            // Emit handshake bytes; rustls signals key transitions via KeyChange.
            // When KeyChange is returned, the keys must be used for future handshake data,
            // which we model by updating `write_level` after queueing any bytes produced.
            for _ in 0..16 {
                self.crypto_buffer.clear();
                let kc = self.connection.write_hs(&mut self.crypto_buffer);
                let produced = !self.crypto_buffer.is_empty();
                if produced {
                    let level = self.write_level;
                    let pending = std::mem::take(&mut self.crypto_buffer);
                    self.queue_crypto_bytes(level, &pending);
                }
                if let Some(kc) = kc {
                    self.install_key_change(kc)?;
                    continue;
                }
                // No key change signaled; if no data was produced, we're done.
                if !produced {
                    break;
                }
            }
            Ok(())
        }

        fn install_handshake_keys(
            &mut self,
            keys: rustls::quic::Keys,
        ) -> Result<(), ConnectionError> {
            let local_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.local.packet.into();
            let remote_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.remote.packet.into();
            let local_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
                keys.local.header.into();
            let remote_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
                keys.remote.header.into();

            let mut crypto = self.crypto.write();
            crypto.seal_handshake = Some(Box::new(RustlsPacketSeal { key: local_pkt.clone() }));
            crypto.open_handshake = Some(Box::new(RustlsPacketOpen { key: remote_pkt.clone() }));
            crypto.hp_handshake = Some(Box::new(RustlsHp { key: local_hp.clone() }));
            crypto.hp_handshake_open = Some(Box::new(RustlsHp { key: remote_hp.clone() }));
            Ok(())
        }

        fn install_1rtt_keys(&mut self, keys: rustls::quic::Keys) -> Result<(), ConnectionError> {
            let local_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.local.packet.into();
            let remote_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.remote.packet.into();
            let local_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
                keys.local.header.into();
            let remote_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
                keys.remote.header.into();

            let mut crypto = self.crypto.write();
            crypto.seal_1rtt = Some(Arc::new(crate::crypto::PacketAeadSeal::Dynamic(Box::new(
                RustlsPacketSeal { key: local_pkt.clone() },
            ))));
            crypto.open_1rtt = Some(Arc::new(crate::crypto::PacketAeadOpen::Dynamic(Box::new(
                RustlsPacketOpen { key: remote_pkt.clone() },
            ))));
            crypto.hp_1rtt = Some(Arc::new(RustlsHp { key: local_hp.clone() }));
            crypto.hp_1rtt_open = Some(Arc::new(RustlsHp { key: remote_hp.clone() }));
            self.pending_local_1rtt.clear();
            self.pending_remote_1rtt.clear();
            Ok(())
        }

        /// Build the client root certificate store: native/webpki roots plus any CA
        /// supplied via `--ca-file` (TLS_CA_PATH_OVERRIDE). Shared by the initial client
        /// connection and the pre-handshake rebuild so both honor the CA override.
        fn build_client_root_store() -> Result<RootCertStore, ConnectionError> {
            let mut roots = RootCertStore::empty();
            let native = load_native_certs();
            if !native.errors.is_empty() {
                log::warn!(
                    "Native cert load had {} errors; continuing with {} certs",
                    native.errors.len(),
                    native.certs.len()
                );
            }
            if native.certs.is_empty() {
                log::warn!("No native certs loaded, using webpki roots");
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            } else {
                for cert in native.certs {
                    roots.add(cert).map_err(|e| {
                        ConnectionError::TlsError(format!("Failed to add native cert: {}", e))
                    })?;
                }
            }
            // Load CA override from --ca-file if set
            if let Some(ca_path) = TLS_CA_PATH_OVERRIDE.get() {
                let ca_data = std::fs::read(ca_path).map_err(|e| {
                    ConnectionError::TlsError(format!("CA file read failed ({}): {}", ca_path, e))
                })?;
                let ca_certs = rustls::pki_types::CertificateDer::pem_slice_iter(&ca_data)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        ConnectionError::TlsError(format!(
                            "CA file parse failed ({}): {}",
                            ca_path, e
                        ))
                    })?;
                for cert in ca_certs {
                    roots.add(cert).map_err(|e| {
                        ConnectionError::TlsError(format!("Failed to add CA cert: {}", e))
                    })?;
                }
                log::info!("Loaded CA certificates from override: {}", ca_path);
            }
            Ok(roots)
        }

        fn create_client_connection(
            verify_peer: bool,
            quic_version: rustls::quic::Version,
            transport_params: Vec<u8>,
        ) -> Result<rustls::quic::Connection, ConnectionError> {
            #[cfg(not(debug_assertions))]
            let _ = verify_peer;
            let roots = Self::build_client_root_store()?;

            let builder = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| ConnectionError::TlsError(format!("Protocol version error: {}", e)))?;
            #[cfg(debug_assertions)]
            let allow_invalid = !verify_peer
                || crate::env_utils::env_flag("QUICFUSCATE_ALLOW_INVALID_CERTS", false);
            #[cfg(not(debug_assertions))]
            let allow_invalid = false;
            let config = if allow_invalid {
                log::warn!("TLS certificate verification is disabled for this debug build");
                #[cfg(debug_assertions)]
                {
                    builder
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(InsecureAcceptAllVerifier))
                        .with_no_client_auth()
                }
                #[cfg(not(debug_assertions))]
                {
                    unreachable!("allow_invalid is always false in release builds")
                }
            } else {
                builder.with_root_certificates(Arc::new(roots)).with_no_client_auth()
            };

            let mut config = config;
            // Enable QUIC
            config.enable_early_data = true;
            config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];
            // Performance settings
            config.max_fragment_size = Some(16384);
            config.enable_sni = true;

            let server_name = ServerName::try_from(DEFAULT_TLS_SNI_HOST)
                .map_err(|_| ConnectionError::TlsError("Invalid server name".into()))?;

            Ok(rustls::quic::Connection::Client(
                rustls::quic::ClientConnection::new(
                    Arc::new(config),
                    quic_version,
                    server_name,
                    transport_params,
                )
                .map_err(|e| {
                    ConnectionError::TlsError(format!("Client connection error: {}", e))
                })?,
            ))
        }

        fn create_server_connection(
            quic_version: rustls::quic::Version,
            transport_params: Vec<u8>,
        ) -> Result<rustls::quic::Connection, ConnectionError> {
            let certs_res = Self::load_certs_from_file();
            let key_res = Self::load_private_key();
            let (certs, key) = match (certs_res, key_res) {
                (Ok(c), Ok(k)) => (c, k),
                (cert_err, key_err) => {
                    if TLS_OVERRIDE_REQUIRED.load(Ordering::Relaxed) {
                        let ce = cert_err
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "-".to_string());
                        let ke =
                            key_err.err().map(|e| e.to_string()).unwrap_or_else(|| "-".to_string());
                        return Err(ConnectionError::TlsError(format!(
                            "TLS cert/key load failed (override required): cert={}, key={}",
                            ce, ke
                        )));
                    }
                    log::warn!(
	                        "No TLS cert/key found on disk. Generating ephemeral self-signed cert (development default)."
	                    );
                    Self::generate_ephemeral_self_signed()?
                }
            };

            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| ConnectionError::TlsError(format!("Protocol version error: {}", e)))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ConnectionError::TlsError(format!("Cert error: {}", e)))?;

            let mut config = config;
            config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];
            config.max_early_data_size = MAX_EARLY_DATA_SIZE.load(Ordering::Relaxed);

            Ok(rustls::quic::Connection::Server(
                rustls::quic::ServerConnection::new(
                    Arc::new(config),
                    quic_version,
                    transport_params,
                )
                .map_err(|e| {
                    ConnectionError::TlsError(format!("Server connection error: {}", e))
                })?,
            ))
        }

        #[cfg(any(feature = "server", feature = "dev-certs"))]
        fn generate_ephemeral_self_signed() -> Result<
            (Vec<CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>),
            ConnectionError,
        > {
            use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
            let mut params = CertificateParams::default();
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(DnType::CountryName, "US");
            params.distinguished_name.push(DnType::OrganizationName, "QuicFuscate");
            params.distinguished_name.push(DnType::CommonName, "localhost");
            let localhost_name = rcgen::Ia5String::try_from("localhost")
                .map_err(|_| ConnectionError::TlsError("Invalid SAN hostname".into()))?;
            params.subject_alt_names = vec![
                SanType::DnsName(localhost_name),
                SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            ];
            let key_pair = rcgen::KeyPair::generate()
                .map_err(|e| ConnectionError::TlsError(format!("Key gen error: {}", e)))?;
            let cert = params
                .self_signed(&key_pair)
                .map_err(|e| ConnectionError::TlsError(format!("Cert gen error: {}", e)))?;

            let certs = vec![CertificateDer::from(cert.der().to_vec())];
            let key_der = key_pair.serialize_der();
            let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
                .map_err(|_| ConnectionError::TlsError("Key conversion error".into()))?;
            Ok((certs, key))
        }

        fn load_certs_from_file() -> Result<Vec<CertificateDer<'static>>, ConnectionError> {
            if let Some(identity) = TLS_SERVER_IDENTITY_OVERRIDE.get() {
                return CertificateDer::pem_slice_iter(&identity.cert_pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| {
                        ConnectionError::TlsError(format!(
                            "Preloaded certificate parse failed: {error}"
                        ))
                    });
            }
            if let Some(path) = TLS_CERT_PATH_OVERRIDE.get().map(|s| s.as_str()) {
                let cert_data = std::fs::read(path).map_err(|e| {
                    ConnectionError::TlsError(format!("Cert read failed ({}): {}", path, e))
                })?;
                let certs = CertificateDer::pem_slice_iter(&cert_data)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        ConnectionError::TlsError(format!("Cert parse failed ({}): {}", path, e))
                    })?;
                return Ok(certs);
            }

            // Try standard locations
            let cert_paths = vec!["certs/server.crt", "/etc/quicfuscate/server.crt", "server.crt"];
            for path in cert_paths {
                if let Ok(cert_data) = std::fs::read(path) {
                    if let Ok(certs) =
                        CertificateDer::pem_slice_iter(&cert_data).collect::<Result<Vec<_>, _>>()
                    {
                        return Ok(certs);
                    }
                }
            }
            Err(ConnectionError::TlsError("No valid certificates found".into()))
        }

        fn load_private_key() -> Result<rustls::pki_types::PrivateKeyDer<'static>, ConnectionError>
        {
            if let Some(identity) = TLS_SERVER_IDENTITY_OVERRIDE.get() {
                return PrivateKeyDer::from_pem_slice(identity.key_pem.as_slice()).map_err(
                    |error| {
                        ConnectionError::TlsError(format!(
                            "Preloaded private key parse failed: {error}"
                        ))
                    },
                );
            }
            if let Some(path) = TLS_KEY_PATH_OVERRIDE.get().map(|s| s.as_str()) {
                let key_data = Zeroizing::new(std::fs::read(path).map_err(|e| {
                    ConnectionError::TlsError(format!("Key read failed ({}): {}", path, e))
                })?);
                let key = PrivateKeyDer::from_pem_slice(&key_data).map_err(|e| {
                    ConnectionError::TlsError(format!("Key parse failed ({}): {}", path, e))
                })?;
                return Ok(key);
            }

            let key_paths = vec!["certs/server.key", "/etc/quicfuscate/server.key", "server.key"];
            for path in key_paths {
                if let Ok(key_data) = std::fs::read(path) {
                    let key_data = Zeroizing::new(key_data);
                    if let Ok(key) = PrivateKeyDer::from_pem_slice(&key_data) {
                        return Ok(key);
                    }
                }
            }
            Err(ConnectionError::TlsError("No valid private key found".into()))
        }

        fn default_transport_params() -> Vec<u8> {
            // QUIC transport parameters in wire format
            let mut params = Vec::new();
            // max_idle_timeout (0x01) = 30000ms
            params.extend_from_slice(&[0x01, 0x02, 0x75, 0x30]);
            // max_udp_payload_size (0x03) = 1472
            params.extend_from_slice(&[0x03, 0x02, 0x05, 0xc0]);
            // initial_max_data (0x04) = 10MB
            params.extend_from_slice(&[0x04, 0x03, 0x98, 0x96, 0x80]);
            // initial_max_stream_data_bidi_local (0x05) = 1MB
            params.extend_from_slice(&[0x05, 0x03, 0x0f, 0x42, 0x40]);
            // initial_max_stream_data_bidi_remote (0x06) = 1MB
            params.extend_from_slice(&[0x06, 0x03, 0x0f, 0x42, 0x40]);
            // initial_max_streams_bidi (0x08) = 100
            params.extend_from_slice(&[0x08, 0x01, 0x64]);
            // initial_max_streams_uni (0x09) = 100
            params.extend_from_slice(&[0x09, 0x01, 0x64]);
            params
        }

        fn apply_profile_to_config(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
            // Store profile and apply minor timing knobs.
            // Intentional sync sleep for TLS timing-channel mitigation.
            // This runs during sync handshake setup, NOT inside an async task.
            self.profile = Some(profile.clone());
            if !profile.cover_performance_mode {
                if let Some(jitter) = profile.timing_jitter {
                    std::thread::sleep(jitter);
                }
            }
            // Best-effort reconfigure only for client side before handshake
            if let rustls::quic::Connection::Client(_) = &self.connection {
                self.rebuild_client_connection(profile)?;
            }
            Ok(())
        }

        fn rebuild_client_connection(
            &mut self,
            profile: &TlsProfile,
        ) -> Result<(), ConnectionError> {
            // Build a fresh ClientConfig with ALPN and early data settings based on profile.
            // Use the shared root store so the --ca-file CA override is honored here too
            // (otherwise the rebuilt connection would only trust native roots and reject
            // a custom CA with UnknownIssuer).
            let roots = Self::build_client_root_store()?;
            let builder = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| ConnectionError::TlsError(format!("Protocol version error: {}", e)))?;
            #[cfg(debug_assertions)]
            let allow_invalid = !self.verify_peer
                || crate::env_utils::env_flag("QUICFUSCATE_ALLOW_INVALID_CERTS", false);
            #[cfg(not(debug_assertions))]
            let allow_invalid = false;
            let cfg = if allow_invalid {
                log::warn!("TLS certificate verification is disabled for this debug build");
                #[cfg(debug_assertions)]
                {
                    builder
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(InsecureAcceptAllVerifier))
                        .with_no_client_auth()
                }
                #[cfg(not(debug_assertions))]
                {
                    unreachable!("allow_invalid is always false in release builds")
                }
            } else {
                builder.with_root_certificates(Arc::new(roots)).with_no_client_auth()
            };
            let mut cfg = cfg;
            // Apply ALPN
            cfg.alpn_protocols =
                profile.alpn_protocols.iter().map(|s| s.as_bytes().to_vec()).collect();
            cfg.enable_early_data = profile.enable_0rtt;
            cfg.enable_sni = true;
            // Create client connection with SNI
            let server_name_str = profile.sni.as_deref().unwrap_or(DEFAULT_TLS_SNI_HOST);
            let server_name = rustls::pki_types::ServerName::try_from(server_name_str)
                .map_err(|_| ConnectionError::TlsError("Invalid server name".into()))?
                .to_owned();
            self.connection = rustls::quic::Connection::Client(
                rustls::quic::ClientConnection::new(
                    Arc::new(cfg),
                    self.quic_version,
                    server_name,
                    self.transport_params.clone(),
                )
                .map_err(|e| {
                    ConnectionError::TlsError(format!("Client connection error: {}", e))
                })?,
            );
            {
                // Drop any CRYPTO bytes produced by the previous client connection instance.
                // The new connection has a new transcript and will re-emit a fresh ClientHello.
                let mut crypto = self.crypto.write();
                crypto.crypto_initial.reset();
                crypto.crypto_handshake.reset();
                crypto.crypto_application.reset();
                crypto.seal_handshake = None;
                crypto.open_handshake = None;
                crypto.hp_handshake = None;
                crypto.hp_handshake_open = None;
                crypto.seal_1rtt = None;
                crypto.open_1rtt = None;
                crypto.hp_1rtt = None;
                crypto.hp_1rtt_open = None;
            }
            self.next_1rtt_secrets = None;
            self.pending_local_1rtt.clear();
            self.pending_remote_1rtt.clear();
            self.handshake_complete = false;
            self.alpn = None;
            self.peer_cert = None;
            self.bytes_sent = 0;
            self.bytes_received = 0;
            self.frame_buffer.clear();
            self.handshake_start = std::time::Instant::now();
            Ok(())
        }
    }

    impl RustlsProviderImpl {
        fn ensure_1rtt_ready(&self) -> Result<(), ConnectionError> {
            let ready = {
                let crypto = self.crypto.read();
                crypto.seal_1rtt.is_some() && crypto.open_1rtt.is_some()
            };
            if !self.handshake_complete || !ready {
                return Err(ConnectionError::TlsError(
                    "key_update requires established 1-RTT keys".to_string(),
                ));
            }
            Ok(())
        }

        fn derive_next_1rtt_pair(&mut self) -> Result<(), ConnectionError> {
            let next = self.next_1rtt_secrets.as_mut().ok_or_else(|| {
                ConnectionError::TlsError(
                    "key_update requires secret-based or rustls-provided update keys".to_string(),
                )
            })?;
            let keys = next.next_packet_keys();
            self.pending_local_1rtt.push_back(keys.local.into());
            self.pending_remote_1rtt.push_back(keys.remote.into());
            Ok(())
        }

        fn update_write_from_rustls_chain(&mut self) -> Result<(), ConnectionError> {
            if self.pending_local_1rtt.is_empty() {
                self.derive_next_1rtt_pair()?;
            }
            let Some(packet_key) = self.pending_local_1rtt.pop_front() else {
                return Err(ConnectionError::TlsError(
                    "missing local 1-RTT key update material".to_string(),
                ));
            };
            let mut crypto = self.crypto.write();
            crypto.rotate_1rtt_write_keypair(Box::new(RustlsPacketSeal { key: packet_key }));
            Ok(())
        }

        fn update_read_from_rustls_chain(&mut self) -> Result<(), ConnectionError> {
            if self.pending_remote_1rtt.is_empty() {
                self.derive_next_1rtt_pair()?;
            }
            let Some(packet_key) = self.pending_remote_1rtt.pop_front() else {
                return Err(ConnectionError::TlsError(
                    "missing remote 1-RTT key update material".to_string(),
                ));
            };
            let mut crypto = self.crypto.write();
            crypto.rotate_1rtt_read_keypair(Box::new(RustlsPacketOpen { key: packet_key }));
            Ok(())
        }
    }

    struct RustlsPacketSeal {
        key: std::sync::Arc<dyn rustls::quic::PacketKey>,
    }

    impl crate::crypto::aead::AeadSeal for RustlsPacketSeal {
        fn seal_with_u64_counter(
            &self,
            counter: u64,
            ad: &[u8],
            buf: &mut [u8],
            len: usize,
            _extra_in: Option<&[u8]>,
        ) -> Result<usize, ConnectionError> {
            let tag_len = self.key.tag_len();
            if buf.len() < len + tag_len {
                return Err(ConnectionError::BufferTooShort);
            }
            let tag = self
                .key
                .encrypt_in_place(counter, ad, &mut buf[..len])
                .map_err(|e| ConnectionError::TlsError(format!("quic seal error: {}", e)))?;
            buf[len..len + tag_len].copy_from_slice(tag.as_ref());
            Ok(len + tag_len)
        }
    }

    struct RustlsPacketOpen {
        key: std::sync::Arc<dyn rustls::quic::PacketKey>,
    }

    impl crate::crypto::aead::AeadOpen for RustlsPacketOpen {
        fn open_with_u64_counter(
            &self,
            counter: u64,
            ad: &[u8],
            buf: &mut [u8],
        ) -> Result<usize, ConnectionError> {
            let pt = self
                .key
                .decrypt_in_place(counter, ad, buf)
                .map_err(|e| ConnectionError::TlsError(format!("quic open error: {}", e)))?;
            Ok(pt.len())
        }
    }

    struct RustlsHp {
        key: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey>,
    }

    impl crate::transport::packet::HeaderProtector for RustlsHp {
        fn new_mask(&self, sample: &[u8]) -> [u8; 5] {
            let sample_len = self.key.sample_len();
            if sample.len() < sample_len {
                super::trace_hp_error(&format!(
                    "hp sample too short have={} need={}",
                    sample.len(),
                    sample_len
                ));
                return [0u8; 5];
            }
            let sample = &sample[..sample_len];

            // Derive the mask bytes by running HP on a controlled header snapshot.
            // We only need the low 5 bits of mask[0] (short header) and the next 4 bytes.
            // Force a 4-byte PN field in the HP helper call. Some implementations derive how many
            // PN bytes to mask from the low bits of `first`, so we set them to 3 (pn_len = 4).
            let first_orig: u8 = crate::transport::packet::FIXED_BIT | 0x03;
            let mut first: u8 = first_orig;
            let mut pn = [0u8; 4];
            if self.key.encrypt_in_place(sample, &mut first, &mut pn).is_err() {
                super::trace_hp_error("hp encrypt_in_place error");
                return [0u8; 5];
            }
            let mask0 = first ^ first_orig;
            super::trace_hp_mask(mask0, pn);
            [mask0, pn[0], pn[1], pn[2], pn[3]]
        }
    }

    impl super::QuicTlsProvider for RustlsProviderImpl {
        fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
            self.apply_profile_to_config(profile)
        }
        fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError> {
            if let Some(ref mut profile) = self.profile {
                profile.sni = Some(name.to_string());
            }
            Ok(())
        }
        fn provide_quic_data(&mut self, _level: Level, data: &[u8]) -> Result<(), ConnectionError> {
            self.bytes_received += data.len();
            self.connection
                .read_hs(data)
                .map_err(|e| ConnectionError::TlsError(format!("Read handshake error: {}", e)))?;
            self.flush_handshake_io()?;
            Ok(())
        }
        fn next_crypto_frame(&mut self, level: Level, max_len: usize) -> Option<(u64, Vec<u8>)> {
            if let Err(e) = self.flush_handshake_io() {
                log::debug!("flush_handshake_io before next_crypto_frame failed: {}", e);
            }
            let mut crypto = self.crypto.write();
            let stream = match level {
                Level::Initial => &mut crypto.crypto_initial,
                Level::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.next_crypto_frame(max_len)
        }
        fn poll_secrets_and_install(
            &mut self,
            _crypto: &Arc<RwLock<CryptoContext>>,
        ) -> Result<(), ConnectionError> {
            self.flush_handshake_io()?;
            if self.peer_transport_params.is_none() {
                self.peer_transport_params =
                    self.connection.quic_transport_parameters().map(<[u8]>::to_vec);
            }
            let have_1rtt = {
                let crypto = self.crypto.read();
                crypto.open_1rtt.is_some() && crypto.seal_1rtt.is_some()
            };
            if !self.handshake_complete && !self.connection.is_handshaking() && have_1rtt {
                self.handshake_complete = true;
                let duration = self.handshake_start.elapsed();
                log::info!(
                    "TLS handshake complete in {:?} with QUIC {:?}",
                    duration,
                    self.quic_version
                );
                if let Some(alpn) = self.connection.alpn_protocol() {
                    self.alpn = Some(String::from_utf8_lossy(alpn).to_string());
                }
                if let Some(certs) = self.connection.peer_certificates() {
                    if let Some(cert) = certs.first() {
                        let cert_bytes = cert.to_vec();
                        // Derive a stable session hint from peer cert + ALPN (pseudo-ticket/master)
                        if let Some(ref cache) = self.session_cache {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(&cert_bytes);
                            if let Some(ref a) = self.alpn {
                                hasher.update(a.as_bytes());
                            }
                            let digest = hasher.finalize();
                            let ticket = crate::secret::SecretBytes::new(
                                digest[..32].to_vec(),
                                "tls_session_ticket",
                            );
                            let master = crate::secret::SecretBytes::new(
                                digest[..32].to_vec(),
                                "tls_session_master_secret",
                            );
                            let data = SessionData {
                                ticket,
                                master_secret: master,
                                alpn: self.alpn.as_deref().unwrap_or("h3").to_owned(),
                                timestamp: std::time::Instant::now(),
                            };
                            let key = self
                                .profile
                                .as_ref()
                                .and_then(|p| p.sni.as_deref())
                                .unwrap_or("default")
                                .to_owned();
                            cache.write().store(key, data);
                        }
                        self.peer_cert = Some(cert_bytes);
                    }
                }
                // Persist basic session info in cache (for future 0-RTT/resumption hints)
                if let Some(ref cache) = self.session_cache {
                    let alpn_s = self.alpn.as_deref().unwrap_or("h3").to_owned();
                    let key = self
                        .profile
                        .as_ref()
                        .and_then(|p| p.sni.as_deref())
                        .unwrap_or("default")
                        .to_owned();
                    let ticket = crate::secret::SecretBytes::new(
                        {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(b"qf-session-ticket");
                            hasher.update(alpn_s.as_bytes());
                            hasher.update(key.as_bytes());
                            hasher.finalize()[..32].to_vec()
                        },
                        "tls_session_ticket",
                    );
                    let data = SessionData {
                        ticket: ticket.clone(),
                        master_secret: crate::secret::SecretBytes::new(
                            ticket.as_slice().to_vec(),
                            "tls_session_master_secret",
                        ),
                        alpn: alpn_s,
                        timestamp: std::time::Instant::now(),
                    };
                    // Touch fields to satisfy usage and sanity-check sizes
                    let _touch = data.ticket.len() + data.master_secret.len() + data.alpn.len();
                    cache.write().store(key, data);
                }
            }
            Ok(())
        }
        fn handshake_complete(&self) -> bool {
            self.handshake_complete
        }
        fn alpn(&self) -> Option<&str> {
            self.alpn.as_deref()
        }
        fn peer_cert(&self) -> Option<Vec<u8>> {
            self.peer_cert.clone()
        }
        fn server_name_get(&self) -> Option<&str> {
            // Server name stored in profile.sni
            self.profile.as_ref().and_then(|p| p.sni.as_deref())
        }
        fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>> {
            if let Some(ref cache) = self.session_cache {
                let key = self
                    .profile
                    .as_ref()
                    .and_then(|p| p.sni.as_deref())
                    .unwrap_or("default")
                    .to_owned();
                if let Some(ticket) = cache.read().get_ticket(&key) {
                    if !ticket.is_empty() {
                        return Some(ticket);
                    }
                }
            }
            if let Some(cert) = self.peer_cert.as_ref() {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(b"qf-session-ticket-fallback");
                hasher.update(cert);
                if let Some(alpn) = self.alpn.as_ref() {
                    hasher.update(alpn.as_bytes());
                }
                if let Some(profile) = self.profile.as_ref() {
                    if let Some(sni) = profile.sni.as_ref() {
                        hasher.update(sni.as_bytes());
                    }
                }
                let digest = hasher.finalize();
                return Some(Zeroizing::new(digest[..32].to_vec()));
            }
            None
        }
        fn enable_0rtt(&mut self) -> Result<(), ConnectionError> {
            self.zero_rtt_enabled = true;
            Ok(())
        }
        fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
            None
        }
        fn export_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
            length: usize,
        ) -> Result<Vec<u8>, ConnectionError> {
            if length == 0 {
                return Err(ConnectionError::TlsError(
                    "export_keying_material requires non-zero length".to_string(),
                ));
            }
            let out = vec![0u8; length];
            self.connection
                .export_keying_material(
                    out,
                    label,
                    if context.is_empty() { None } else { Some(context) },
                )
                .map_err(|e| {
                    ConnectionError::TlsError(format!("export_keying_material failed: {}", e))
                })
        }
        fn get_quic_transport_params(&self) -> Vec<u8> {
            self.transport_params.clone()
        }
        fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError> {
            self.peer_transport_params = Some(params.to_vec());
            Ok(())
        }
        fn peer_quic_transport_params(&self) -> Option<Vec<u8>> {
            self.peer_transport_params.clone()
        }
        fn key_update(&mut self) -> Result<(), ConnectionError> {
            self.key_update_write()?;
            self.key_update_read()
        }
        fn key_update_read(&mut self) -> Result<(), ConnectionError> {
            self.ensure_1rtt_ready()?;
            if self.crypto.write().key_update_1rtt_read() {
                return Ok(());
            }
            self.update_read_from_rustls_chain()
        }
        fn key_update_write(&mut self) -> Result<(), ConnectionError> {
            self.ensure_1rtt_ready()?;
            if self.crypto.write().key_update_1rtt_write() {
                return Ok(());
            }
            self.update_write_from_rustls_chain()
        }
        fn provider_name(&self) -> &str {
            "rustls"
        }
        fn supports_ch_override(&self) -> bool {
            false
        }
    }

    pub(super) fn make(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
    ) -> Result<RustlsProviderImpl, ConnectionError> {
        RustlsProviderImpl::new(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
        )
    }
}

/// Thin wrapper around the rustls QUIC provider implementing `QuicTlsProvider`.
pub struct RustlsProvider(rustls_provider::RustlsProviderImpl);

impl RustlsProvider {
    /// Create a new rustls-backed TLS provider for client or server mode.
    pub fn new(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
    ) -> Result<Self, ConnectionError> {
        Ok(Self(rustls_provider::make(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
        )?))
    }
}

impl QuicTlsProvider for RustlsProvider {
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
        self.0.configure(profile)
    }
    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError> {
        self.0.set_server_name(name)
    }
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError> {
        self.0.provide_quic_data(level, data)
    }
    fn next_crypto_frame(&mut self, level: Level, max_len: usize) -> Option<(u64, Vec<u8>)> {
        self.0.next_crypto_frame(level, max_len)
    }
    fn poll_secrets_and_install(
        &mut self,
        crypto: &Arc<RwLock<CryptoContext>>,
    ) -> Result<(), ConnectionError> {
        self.0.poll_secrets_and_install(crypto)
    }
    fn handshake_complete(&self) -> bool {
        self.0.handshake_complete()
    }
    fn alpn(&self) -> Option<&str> {
        self.0.alpn()
    }
    fn peer_cert(&self) -> Option<Vec<u8>> {
        self.0.peer_cert()
    }
    fn server_name_get(&self) -> Option<&str> {
        self.0.server_name_get()
    }
    fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.0.session_ticket()
    }
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError> {
        self.0.enable_0rtt()
    }
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.0.get_0rtt_keys()
    }
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, ConnectionError> {
        self.0.export_keying_material(label, context, length)
    }
    fn get_quic_transport_params(&self) -> Vec<u8> {
        self.0.get_quic_transport_params()
    }
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError> {
        self.0.set_peer_transport_params(params)
    }
    fn peer_quic_transport_params(&self) -> Option<Vec<u8>> {
        self.0.peer_quic_transport_params()
    }
    fn key_update(&mut self) -> Result<(), ConnectionError> {
        self.0.key_update()
    }
    fn key_update_read(&mut self) -> Result<(), ConnectionError> {
        self.0.key_update_read()
    }
    fn key_update_write(&mut self) -> Result<(), ConnectionError> {
        self.0.key_update_write()
    }
    fn provider_name(&self) -> &str {
        self.0.provider_name()
    }
    fn supports_ch_override(&self) -> bool {
        self.0.supports_ch_override()
    }
}

impl RustlsProvider {
    pub fn apply_session_hint_to_profile(&mut self) {
        if self.0.session_cache.is_some() {
            if let Some(ref mut prof) = self.0.profile {
                if !prof.alpn_protocols.is_empty() && prof.alpn_protocols[0] != "h3" {
                    prof.alpn_protocols.retain(|p| p != "h3");
                    prof.alpn_protocols.insert(0, "h3".into());
                }
            }
        }
    }
}

// BoringSSL/RealTLS code was removed from src and centralized in archive/boringisland.rs.
