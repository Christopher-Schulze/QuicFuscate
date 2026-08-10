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
use qf_stealth::{TlsCoverCipherPreference, TlsCoverCipherSuite};
use qf_transport_types::QUIC_FIXED_BIT;
#[cfg(test)]
use qf_transport_version::VersionInformation;
use qf_transport_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_V2};

include!("qftls/tls_cover_provider.rs");

/// Compatibility export for the root TLS namespace. The canonical contract lives in the
/// dependency-free transport-types leaf.
pub use qf_transport_types::QuicEncryptionLevel as Level;

/// Sensitive keying material returned by the TLS exporter.
pub type SensitiveKeyingMaterial = Zeroizing<Vec<u8>>;

/// Historical TLS name for the canonical individual memory-lock status.
pub use qf_memory_lock::MemoryLockAllocationStatus as TlsKeyLockStatus;

static TLS_CERT_PATH_OVERRIDE: OnceLock<String> = OnceLock::new();
static TLS_KEY_PATH_OVERRIDE: OnceLock<String> = OnceLock::new();
static TLS_SERVER_IDENTITY_OVERRIDE: OnceLock<PreloadedServerIdentity> = OnceLock::new();
static TLS_OVERRIDE_REQUIRED: AtomicBool = AtomicBool::new(false);
/// Configurable max early data size for server TLS config.
/// RFC 9001 §4.6.1: QUIC requires this to be either 0 (no 0-RTT) or 0xFFFF_FFFF (0-RTT enabled).
/// Default is u32::MAX (0-RTT offered). Set to 0 to disable 0-RTT.
/// Set via `set_max_early_data_size()` before server connection creation.
static MAX_EARLY_DATA_SIZE: AtomicU32 = AtomicU32::new(u32::MAX);

/// Reports the result of publishing a preloaded server identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsIdentityPreloadStatus {
    /// This call published the process-lifetime identity owner.
    Loaded { key_lock: TlsKeyLockStatus },
    /// The exact same certificate and key were already published.
    AlreadyLoaded,
}

struct LockedKeyMaterial {
    bytes: Zeroizing<Vec<u8>>,
    status: TlsKeyLockStatus,
}

impl LockedKeyMaterial {
    fn new(bytes: Zeroizing<Vec<u8>>, lock_memory: bool) -> Self {
        let status = if !lock_memory {
            TlsKeyLockStatus::Disabled
        } else if qf_memory_lock::process_memory_lock_covers_future_allocations() {
            TlsKeyLockStatus::CoveredByProcess
        } else {
            try_lock_key_material(bytes.as_slice())
        };
        Self { bytes, status }
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn status(&self) -> TlsKeyLockStatus {
        self.status
    }
}

impl Drop for LockedKeyMaterial {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().fill(0);
        if self.status == TlsKeyLockStatus::Locked {
            unlock_key_material(self.bytes.as_ptr(), self.bytes.len());
        }
    }
}

struct PreloadedServerIdentity {
    cert_pem: Vec<u8>,
    key_pem: LockedKeyMaterial,
}

impl PreloadedServerIdentity {
    fn new(cert_pem: Vec<u8>, key_pem: Zeroizing<Vec<u8>>, lock_memory: bool) -> Self {
        Self { cert_pem, key_pem: LockedKeyMaterial::new(key_pem, lock_memory) }
    }

    fn matches(&self, cert_pem: &[u8], key_pem: &[u8]) -> bool {
        self.cert_pem == cert_pem && self.key_pem.as_slice() == key_pem
    }
}

#[cfg(unix)]
fn try_lock_key_material(bytes: &[u8]) -> TlsKeyLockStatus {
    // SAFETY: `bytes` is a live allocation owned by `LockedKeyMaterial` for the
    // complete duration of the syscall and has the exact length passed here.
    if unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) } == 0 {
        TlsKeyLockStatus::Locked
    } else {
        let error = std::io::Error::last_os_error();
        log::warn!("Failed to lock preloaded TLS private key in memory: {error}");
        TlsKeyLockStatus::Unavailable
    }
}

#[cfg(not(unix))]
fn try_lock_key_material(_bytes: &[u8]) -> TlsKeyLockStatus {
    log::debug!("Individual TLS private-key memory locking is unsupported on this platform");
    TlsKeyLockStatus::Unavailable
}

#[cfg(unix)]
fn unlock_key_material(ptr: *const u8, len: usize) {
    // SAFETY: the pointer and length are the exact allocation range previously
    // locked by this guard, and the allocation remains alive during the call.
    if unsafe { libc::munlock(ptr.cast(), len) } != 0 {
        log::error!(
            "Failed to unlock preloaded TLS private-key memory ({} bytes): {}",
            len,
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(unix))]
fn unlock_key_material(_ptr: *const u8, _len: usize) {}

/// Tell the qftls owner whether process-wide locking covers future allocations.
///
/// Standalone startup calls this only after a successful
/// `mlockall(MCL_CURRENT | MCL_FUTURE)` operation. `MCL_CURRENT` alone is not
/// sufficient because a later TLS key allocation still needs its own lock.
#[doc(hidden)]
pub fn set_process_memory_lock_covers_future_allocations(enabled: bool) {
    qf_memory_lock::set_process_memory_lock_covers_future_allocations(enabled);
}

fn publish_preloaded_identity(
    slot: &OnceLock<PreloadedServerIdentity>,
    identity: PreloadedServerIdentity,
) -> Result<TlsIdentityPreloadStatus, ConnectionError> {
    let key_lock = identity.key_pem.status();
    match slot.set(identity) {
        Ok(()) => Ok(TlsIdentityPreloadStatus::Loaded { key_lock }),
        Err(rejected) => {
            let same_identity = slot.get().is_some_and(|existing| {
                existing.matches(&rejected.cert_pem, rejected.key_pem.as_slice())
            });
            drop(rejected);
            if same_identity {
                Ok(TlsIdentityPreloadStatus::AlreadyLoaded)
            } else {
                Err(ConnectionError::TlsError(
                    "TLS server identity already preloaded with a different certificate or private key"
                        .to_string(),
                ))
            }
        }
    }
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
///
/// `lock_memory` is the canonical security policy for the individual key
/// buffer. Lock failure is best-effort for compatibility with finite
/// `RLIMIT_MEMLOCK`; the returned status and startup warning make degradation
/// observable. The accepted identity is process-lifetime-owned by the static
/// `OnceLock`; rejected duplicate/conflicting values are dropped through the
/// exact-range guard and therefore unlock their own successful `mlock` call.
pub fn preload_tls_server_identity(
    cert_path: &str,
    key_path: &str,
    lock_memory: bool,
) -> Result<TlsIdentityPreloadStatus, ConnectionError> {
    let cert_pem = std::fs::read(cert_path).map_err(|error| {
        ConnectionError::TlsError(format!("Cert read failed ({cert_path}): {error}"))
    })?;
    let key_pem = Zeroizing::new(std::fs::read(key_path).map_err(|error| {
        ConnectionError::TlsError(format!("Key read failed ({key_path}): {error}"))
    })?);
    rustls_provider::validate_server_identity_pem(&cert_pem, key_pem.as_slice())?;

    if let Some(existing) = TLS_SERVER_IDENTITY_OVERRIDE.get() {
        if existing.matches(&cert_pem, key_pem.as_slice()) {
            return Ok(TlsIdentityPreloadStatus::AlreadyLoaded);
        }
        return Err(ConnectionError::TlsError(
            "TLS server identity already preloaded with a different certificate or private key"
                .to_string(),
        ));
    }

    let identity = PreloadedServerIdentity::new(cert_pem, key_pem, lock_memory);
    let status = publish_preloaded_identity(&TLS_SERVER_IDENTITY_OVERRIDE, identity)?;
    if matches!(status, TlsIdentityPreloadStatus::Loaded { .. }) {
        set_tls_cert_key_paths(cert_path, key_path);
    }
    Ok(status)
}

// ===============================
// Core Types and Trait
// ===============================

/// Browser-shaped TLS profile contract and fingerprint conversion owned by qf-stealth.
pub use qf_stealth::{profile_from_fingerprint, TlsProfile};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use zeroize::Zeroize;

    #[cfg(feature = "rcgen")]
    struct IdentityFixture {
        directory: std::path::PathBuf,
        cert_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
    }

    #[cfg(feature = "rcgen")]
    impl IdentityFixture {
        fn new(label: &str) -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock must be after the Unix epoch")
                .as_nanos();
            let directory = std::env::temp_dir()
                .join(format!("quicfuscate-qftls-identity-{}-{label}-{stamp}", std::process::id()));
            std::fs::create_dir_all(&directory).expect("create TLS identity fixture directory");
            let cert_path = directory.join("server.crt");
            let key_path = directory.join("server.key");
            let mut hierarchy =
                crate::pki::generate_hierarchy("localhost", label).expect("generate TLS fixture");
            crate::pki::write_cert_chain_pem(
                &hierarchy.server_leaf.cert_der,
                &hierarchy.intermediate_ca.cert_der,
                &cert_path,
            )
            .expect("write TLS certificate fixture");
            crate::pki::write_key_pem(&mut hierarchy.server_leaf.key_der, &key_path)
                .expect("write TLS private-key fixture");
            Self { directory, cert_path, key_path }
        }
    }

    #[cfg(feature = "rcgen")]
    impl Drop for IdentityFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn preload_identity_duplicate_and_conflict_contract_is_isolated() {
        const CHILD_ENV: &str = "QUICFUSCATE_QFTLS_PRELOAD_CHILD";
        const TEST_NAME: &str =
            "qftls::tests::preload_identity_duplicate_and_conflict_contract_is_isolated";

        if std::env::var_os(CHILD_ENV).is_some() {
            let first = IdentityFixture::new("first");
            let mismatched = IdentityFixture::new("mismatched");
            let mismatch_error = preload_tls_server_identity(
                first.cert_path.to_str().expect("fixture certificate path is UTF-8"),
                mismatched.key_path.to_str().expect("fixture key path is UTF-8"),
                true,
            )
            .expect_err("a certificate and unrelated private key must be rejected");
            assert!(matches!(
                mismatch_error,
                ConnectionError::TlsError(message)
                    if message.contains("correspondence validation failed")
            ));

            let first_status = preload_tls_server_identity(
                first.cert_path.to_str().expect("fixture certificate path is UTF-8"),
                first.key_path.to_str().expect("fixture key path is UTF-8"),
                true,
            )
            .expect("first TLS identity must preload");
            assert!(matches!(
                first_status,
                TlsIdentityPreloadStatus::Loaded {
                    key_lock: TlsKeyLockStatus::Locked
                        | TlsKeyLockStatus::CoveredByProcess
                        | TlsKeyLockStatus::Unavailable
                }
            ));

            let same_status = preload_tls_server_identity(
                first.cert_path.to_str().expect("fixture certificate path is UTF-8"),
                first.key_path.to_str().expect("fixture key path is UTF-8"),
                true,
            )
            .expect("same TLS identity must be idempotent");
            assert_eq!(same_status, TlsIdentityPreloadStatus::AlreadyLoaded);

            let conflict = IdentityFixture::new("conflict");
            let error = preload_tls_server_identity(
                conflict.cert_path.to_str().expect("fixture certificate path is UTF-8"),
                conflict.key_path.to_str().expect("fixture key path is UTF-8"),
                true,
            )
            .expect_err("a different TLS identity must be rejected");
            assert!(matches!(
                error,
                ConnectionError::TlsError(message)
                    if message.contains("different certificate or private key")
            ));
            return;
        }

        let output = std::process::Command::new(
            std::env::current_exe().expect("resolve qftls test executable"),
        )
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(CHILD_ENV, "1")
        .env("RUST_TEST_THREADS", "1")
        .output()
        .expect("spawn isolated qftls preload test");
        assert!(
            output.status.success(),
            "isolated qftls preload test failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn preloaded_identity_publication_releases_rejected_values() {
        let slot = OnceLock::new();
        let first = PreloadedServerIdentity::new(
            b"first-cert".to_vec(),
            Zeroizing::new(b"first-key".to_vec()),
            true,
        );
        assert!(matches!(
            publish_preloaded_identity(&slot, first),
            Ok(TlsIdentityPreloadStatus::Loaded { .. })
        ));

        let same = PreloadedServerIdentity::new(
            b"first-cert".to_vec(),
            Zeroizing::new(b"first-key".to_vec()),
            true,
        );
        assert_eq!(
            publish_preloaded_identity(&slot, same),
            Ok(TlsIdentityPreloadStatus::AlreadyLoaded)
        );

        let conflict = PreloadedServerIdentity::new(
            b"other-cert".to_vec(),
            Zeroizing::new(b"other-key".to_vec()),
            true,
        );
        assert!(matches!(
            publish_preloaded_identity(&slot, conflict),
            Err(ConnectionError::TlsError(message))
                if message.contains("different certificate or private key")
        ));
    }

    struct ZeroizeDropProbe {
        was_zeroized: Arc<AtomicBool>,
    }

    impl Zeroize for ZeroizeDropProbe {
        fn zeroize(&mut self) {
            self.was_zeroized.store(true, Ordering::Release);
        }
    }

    impl Drop for ZeroizeDropProbe {
        fn drop(&mut self) {
            assert!(
                self.was_zeroized.load(Ordering::Acquire),
                "Zeroizing must erase the sensitive owner before its inner value drops"
            );
        }
    }

    #[test]
    fn sensitive_keying_material_owner_zeroizes_before_drop() {
        let output: SensitiveKeyingMaterial = SensitiveKeyingMaterial::new(vec![0xA5; 32]);
        assert_eq!(output.len(), 32);

        let was_zeroized = Arc::new(AtomicBool::new(false));
        {
            let _owner = Zeroizing::new(ZeroizeDropProbe { was_zeroized: was_zeroized.clone() });
        }
        assert!(was_zeroized.load(Ordering::Acquire));
    }

    fn client_hello_cipher_suites(frame: &[u8]) -> Vec<u16> {
        assert!(frame.len() >= 4, "ClientHello handshake header is truncated");
        assert_eq!(frame[0], 0x01, "expected a ClientHello handshake");
        let body_len = usize::try_from(u32::from_be_bytes([0, frame[1], frame[2], frame[3]]))
            .expect("ClientHello body length");
        assert!(frame.len() >= 4 + body_len, "ClientHello body is truncated");
        let body = &frame[4..4 + body_len];
        assert!(body.len() >= 35, "ClientHello body lacks version/random/session ID");
        let session_id_len = usize::from(body[34]);
        let suites_len_offset = 35 + session_id_len;
        assert!(body.len() >= suites_len_offset + 2, "cipher-suite length is truncated");
        let suites_len =
            usize::from(u16::from_be_bytes([body[suites_len_offset], body[suites_len_offset + 1]]));
        let suites_start = suites_len_offset + 2;
        assert_eq!(suites_len % 2, 0, "cipher-suite vector has an odd length");
        assert!(body.len() >= suites_start + suites_len, "cipher-suite vector is truncated");
        body[suites_start..suites_start + suites_len]
            .chunks_exact(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .collect()
    }

    #[test]
    fn v2_provider_carries_version_information_transport_parameter() {
        let crypto = Arc::new(RwLock::new(CryptoContext::default()));
        let information = VersionInformation {
            chosen: PROTOCOL_VERSION_V2,
            available: vec![PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
        }
        .encode_parameter()
        .unwrap();
        let provider =
            create_provider_for_version(false, crypto, false, PROTOCOL_VERSION_V2, &information)
                .expect("create v2 provider");
        assert!(provider.get_quic_transport_params().ends_with(&information));
    }

    #[test]
    fn rustls_client_hello_policy_excludes_chacha_for_chrome_and_firefox() {
        let crypto = Arc::new(RwLock::new(CryptoContext::default()));
        let mut provider =
            RustlsProvider::new(false, Arc::clone(&crypto), false, PROTOCOL_VERSION, &[])
                .expect("client provider");

        for mut profile in [TlsProfile::chrome_130(), TlsProfile::firefox_133()] {
            // This test owns cipher-suite policy only. Cosmetic profile timing
            // is covered by profile_delay_tests and must not gate ClientHello
            // inspection on an immediate frame.
            profile.timing_jitter = None;
            provider.configure(&profile).expect("configure profile");
            let (_, frame) = provider
                .next_crypto_frame(Level::Initial, usize::MAX)
                .expect("next initial frame")
                .expect("initial ClientHello");
            let suites = client_hello_cipher_suites(&frame);
            assert!(
                !suites.iter().any(|suite| matches!(*suite, 0x1303 | 0xCCA8 | 0xCCA9)),
                "real rustls ClientHello for {} contains ChaCha: {:?}",
                profile.name,
                suites
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
    fn chrome_extension_order_uses_unique_registered_extension_types() {
        let profile = TlsProfile::chrome_130();
        let known_chrome_extensions = [
            0x0000, 0x000d, 0x0010, 0x0017, 0x001b, 0x0023, 0x0029, 0x002b, 0x002d, 0x0033, 0x0039,
            0x0a0a, 0xfe0d, 0xff01,
        ];

        let mut unique_extensions = profile.extension_order.clone();
        unique_extensions.sort_unstable();
        unique_extensions.dedup();
        assert_eq!(
            unique_extensions.len(),
            profile.extension_order.len(),
            "Chrome extension order must not contain duplicate IDs"
        );
        assert!(
            profile
                .extension_order
                .iter()
                .all(|extension| known_chrome_extensions.contains(extension)),
            "Chrome extension order contains an unknown extension type: {:?}",
            profile.extension_order
        );
        assert_eq!(profile.extension_order.iter().filter(|&&id| id == 0x0000).count(), 1);
        assert_eq!(profile.extension_order.iter().filter(|&&id| id == 0xff01).count(), 1);
        assert_eq!(profile.extension_order.iter().filter(|&&id| id == 0x001b).count(), 1);
        assert!(!profile.extension_order.contains(&0x0019));
    }

    #[test]
    fn tls_provider_defaults_to_rustls_owner() {
        let crypto = Arc::new(RwLock::new(CryptoContext::default()));
        let provider = create_provider(false, crypto).unwrap();

        assert!(provider.provider_name().starts_with("rustls"));
    }

    #[test]
    fn tls_cover_support_matches_provider_name() {
        let cover_enabled = std::env::var("QUICFUSCATE_TLS_COVER")
            .map(|raw| raw != "0" && !raw.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        let crypto = Arc::new(RwLock::new(CryptoContext::default()));
        let provider = create_provider(false, crypto).unwrap();

        assert!(!provider.supports_ch_override());
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
    fn next_crypto_frame(
        &mut self,
        level: Level,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError>;
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
    /// Export keying material (for QUIC key update) with an erasing owner.
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<SensitiveKeyingMaterial, ConnectionError>;
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
    create_provider_for_version(is_server, crypto, verify_peer, PROTOCOL_VERSION, &[])
}

pub(crate) fn create_provider_for_version(
    is_server: bool,
    crypto: Arc<RwLock<CryptoContext>>,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_for_version_with_ca(
        is_server,
        crypto,
        verify_peer,
        version,
        version_information_parameter,
        None,
    )
}

pub(crate) fn create_provider_for_version_with_ca(
    is_server: bool,
    crypto: Arc<RwLock<CryptoContext>>,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    verify_locations_file: Option<&str>,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    let environment = crate::env_utils::EnvSnapshot::capture();
    create_provider_for_version_with_ca_with_snapshot(
        is_server,
        crypto,
        verify_peer,
        version,
        version_information_parameter,
        verify_locations_file,
        &environment,
    )
}

pub(crate) fn create_provider_for_version_with_ca_with_snapshot(
    is_server: bool,
    crypto: Arc<RwLock<CryptoContext>>,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    verify_locations_file: Option<&str>,
    environment: &crate::env_utils::EnvSnapshot,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_for_version_with_ca_with_snapshot_and_clock(
        is_server,
        crypto,
        verify_peer,
        version,
        version_information_parameter,
        verify_locations_file,
        environment,
        &crate::time_source::ProtocolClock::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_provider_for_version_with_ca_with_snapshot_and_clock(
    is_server: bool,
    crypto: Arc<RwLock<CryptoContext>>,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    verify_locations_file: Option<&str>,
    environment: &crate::env_utils::EnvSnapshot,
    clock: &crate::time_source::ProtocolClock,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    Ok(Box::new(CombinedProvider::new_with_ca_with_snapshot_and_clock(
        is_server,
        crypto,
        verify_peer,
        version,
        version_information_parameter,
        verify_locations_file,
        environment,
        clock,
    )?))
}

// ===============================
// Combined Provider (rustls + optional TLS Cover)
// rustls remains the TLS protocol owner; cover is an overlay only.
// ===============================

/// Combined TLS provider composing rustls (protocol owner) with an optional TLS cover overlay.
pub struct CombinedProvider {
    rustls: RustlsProvider,
    cover: Option<TlsCoverProvider>,
}

impl CombinedProvider {
    fn env_string(
        environment: &crate::env_utils::EnvSnapshot,
        name: &str,
        default: &str,
    ) -> String {
        environment.first([name]).unwrap_or_else(|| default.to_string())
    }

    /// Create a new combined provider (rustls + optional TLS cover).
    pub fn new(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            None,
        )
    }

    fn new_with_ca(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        verify_locations_file: Option<&str>,
    ) -> Result<Self, ConnectionError> {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_ca_with_snapshot(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            verify_locations_file,
            &environment,
        )
    }

    fn new_with_ca_with_snapshot(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        verify_locations_file: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca_with_snapshot_and_clock(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            verify_locations_file,
            environment,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_ca_with_snapshot_and_clock(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        verify_locations_file: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<Self, ConnectionError> {
        let rustls = RustlsProvider::new_with_ca_with_snapshot_and_clock(
            is_server,
            crypto.clone(),
            verify_peer,
            version,
            version_information_parameter,
            verify_locations_file,
            environment,
            clock,
        )?;
        // Cover is optional and intentionally separated from TLS protocol semantics.
        // It can be disabled via ENV QUICFUSCATE_TLS_COVER=0.
        // In base/performance mode, cover keeps traffic shape with reduced timing overhead.
        let cover_enabled = environment.flag("QUICFUSCATE_TLS_COVER", true);
        let cover = if cover_enabled {
            // Check stealth mode to determine TLS Cover behavior
            let stealth_mode = Self::env_string(environment, "QUICFUSCATE_STEALTH_MODE", "stealth");

            let mut tls_cover =
                TlsCoverProvider::new_with_snapshot(is_server, crypto.clone(), environment)?;

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
            if environment.flag("QUICFUSCATE_TLS_COVER_ROTATE", false) {
                log::info!("TLS Cover profile rotation enabled");
            }

            // Enable telemetry if requested
            if environment.flag("QUICFUSCATE_TLS_COVER_TELEMETRY", false) {
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

    fn next_crypto_frame(
        &mut self,
        level: Level,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        // rustls-driven handshake frames always take priority.
        if let Some(frame) = self.rustls.next_crypto_frame(level, max_len)? {
            return Ok(Some(frame));
        }
        // Emit optional cover decoy frames before real handshake completion.
        if let Some(ref mut c) = self.cover {
            if !self.rustls.handshake_complete() {
                return c.next_crypto_frame(level, max_len);
            }
        }
        Ok(None)
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
    ) -> Result<SensitiveKeyingMaterial, ConnectionError> {
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
        // TLS Cover emits synthetic decoy records only; rustls owns the real ClientHello.
        false
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
    use std::time::Instant;
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
        let key = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|error| ConnectionError::TlsError(format!("Key parse failed: {error}")))?;
        ServerConfig::builder_with_provider(Arc::new(crypto_provider_without_chacha()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| {
                ConnectionError::TlsError(format!("TLS protocol validation failed: {error}"))
            })?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map(|_| ())
            .map_err(|error| {
                ConnectionError::TlsError(format!(
                    "Certificate/private-key correspondence validation failed: {error}"
                ))
            })
    }

    /// Full-featured rustls QUIC TLS provider with session resumption, 0-RTT, and PQ support.
    /// Build the shared rustls provider with the project's real-TLS ChaCha policy.
    ///
    /// This provider is used on both client and server connections. TLS Cover's
    /// synthetic record cipher remains independently configurable and is not part
    /// of this ClientHello negotiation policy.
    fn crypto_provider_without_chacha() -> rustls::crypto::CryptoProvider {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites.retain(|suite| {
            !matches!(
                suite.suite(),
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            )
        });
        provider
    }

    pub struct RustlsProviderImpl {
        /// Active rustls QUIC connection (client or server side).
        pub connection: rustls::quic::Connection,
        /// Monotonic clock shared with the owning QUIC connection.
        pub clock: crate::time_source::ProtocolClock,
        /// Shared crypto context for installing packet protection keys.
        pub crypto: Arc<RwLock<CryptoContext>>,
        /// True if this is a server-side provider.
        pub is_server: bool,
        /// Immutable environment generation used by this TLS runtime owner.
        #[cfg(debug_assertions)]
        pub environment: Arc<crate::env_utils::EnvSnapshot>,
        /// Whether the client verifies the server certificate.
        #[cfg(debug_assertions)]
        pub verify_peer: bool,
        /// Client-scoped CA bundle path copied from the owning transport config.
        pub client_ca_path: Option<String>,
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
        /// Earliest instant at which profile-gated handshake bytes may be emitted.
        pub profile_ready_at: Option<Instant>,
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
            for label in ["tls_session_ticket"] {
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

    #[cfg(test)]
    mod profile_delay_tests {
        use super::*;
        use std::time::Duration;

        #[test]
        fn profile_jitter_is_scheduled_without_blocking_configuration() {
            let crypto = Arc::new(RwLock::new(CryptoContext::default()));
            let mut provider =
                RustlsProviderImpl::new_with_ca(false, crypto, false, PROTOCOL_VERSION, &[], None)
                    .expect("client provider");
            let mut profile = TlsProfile::chrome_130();
            profile.timing_jitter = Some(Duration::from_secs(2));

            provider.apply_profile_to_config(&profile).expect("profile configuration");

            assert!(
                provider.profile_ready_at.is_some_and(|ready_at| ready_at > provider.clock.now()),
                "profile configuration must retain a future readiness deadline"
            );
            assert!(provider
                .next_crypto_frame(Level::Initial, 1200)
                .expect("profile delay probe")
                .is_none());
        }
    }

    #[cfg(test)]
    mod ca_scope_tests {
        use super::*;
        use std::path::{Path, PathBuf};

        struct CaFixture {
            directory: PathBuf,
            path: PathBuf,
        }

        impl CaFixture {
            fn new(organization: &str) -> Self {
                let directory = std::env::temp_dir().join(format!(
                    "quicfuscate-qftls-ca-{}-{}",
                    std::process::id(),
                    organization.replace(' ', "-")
                ));
                std::fs::create_dir_all(&directory).expect("create CA fixture directory");
                let path = directory.join("ca.crt");
                let hierarchy = crate::pki::generate_hierarchy("example.com", organization)
                    .expect("generate CA fixture hierarchy");
                crate::pki::write_ca_cert_pem(&hierarchy.root_ca.cert_der, &path)
                    .expect("write CA fixture");
                Self { directory, path }
            }

            fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for CaFixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.directory);
            }
        }

        fn client_crypto() -> Arc<RwLock<CryptoContext>> {
            Arc::new(RwLock::new(CryptoContext::default()))
        }

        #[test]
        fn client_ca_root_store_rejects_missing_and_invalid_pem() {
            let fixture = CaFixture::new("missing-and-invalid");
            let missing = fixture.directory.join("missing.crt");
            let missing_path = missing.to_str().expect("UTF-8 fixture path");
            let missing_error = RustlsProviderImpl::build_client_root_store(Some(missing_path))
                .expect_err("missing CA file must fail closed");
            assert!(missing_error.to_string().contains(missing_path));

            let invalid = fixture.directory.join("invalid.crt");
            std::fs::write(&invalid, b"not a certificate").expect("write invalid CA fixture");
            let invalid_path = invalid.to_str().expect("UTF-8 fixture path");
            let invalid_error = RustlsProviderImpl::build_client_root_store(Some(invalid_path))
                .expect_err("invalid PEM must fail closed");
            let invalid_message = invalid_error.to_string();
            assert!(invalid_message.contains(invalid_path));
            assert!(!invalid_message.contains("not a certificate"));
        }

        #[test]
        fn client_ca_roots_are_scoped_per_provider_and_repeatable() {
            let first = CaFixture::new("first-client");
            let second = CaFixture::new("second-client");
            let first_path = first.path().to_str().expect("UTF-8 fixture path");
            let second_path = second.path().to_str().expect("UTF-8 fixture path");

            let first_roots =
                RustlsProviderImpl::build_client_root_store(Some(first_path)).expect("first CA");
            let second_roots =
                RustlsProviderImpl::build_client_root_store(Some(second_path)).expect("second CA");
            let first_subject =
                first_roots.roots.last().expect("first custom root").subject.as_ref().to_vec();
            let second_subject =
                second_roots.roots.last().expect("second custom root").subject.as_ref().to_vec();
            assert_ne!(first_subject, second_subject, "different providers must not share roots");

            let first_provider = RustlsProviderImpl::new_with_ca(
                false,
                client_crypto(),
                false,
                PROTOCOL_VERSION,
                &[],
                Some(first_path),
            )
            .expect("first client provider");
            let second_provider = RustlsProviderImpl::new_with_ca(
                false,
                client_crypto(),
                false,
                PROTOCOL_VERSION,
                &[],
                Some(second_path),
            )
            .expect("second client provider");
            let repeated_provider = RustlsProviderImpl::new_with_ca(
                false,
                client_crypto(),
                false,
                PROTOCOL_VERSION,
                &[],
                Some(first_path),
            )
            .expect("repeated same-path client provider");

            assert_eq!(first_provider.client_ca_path.as_deref(), Some(first_path));
            assert_eq!(second_provider.client_ca_path.as_deref(), Some(second_path));
            assert_eq!(repeated_provider.client_ca_path.as_deref(), Some(first_path));
        }
    }

    #[cfg(test)]
    mod cipher_policy_tests {
        use super::*;

        #[test]
        fn shared_client_server_provider_excludes_chacha() {
            let provider = crypto_provider_without_chacha();
            assert!(provider.cipher_suites.iter().any(|suite| {
                matches!(
                    suite.suite(),
                    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                        | rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                )
            }));
            assert!(provider.cipher_suites.iter().all(|suite| {
                !matches!(
                    suite.suite(),
                    rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                        | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                )
            }));
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
        #[cfg(test)]
        pub fn new_with_ca(
            is_server: bool,
            crypto: Arc<RwLock<CryptoContext>>,
            verify_peer: bool,
            version: u32,
            version_information_parameter: &[u8],
            client_ca_path: Option<&str>,
        ) -> Result<Self, ConnectionError> {
            let environment = crate::env_utils::EnvSnapshot::capture();
            Self::new_with_ca_with_snapshot(
                is_server,
                crypto,
                verify_peer,
                version,
                version_information_parameter,
                client_ca_path,
                &environment,
            )
        }

        #[allow(dead_code)]
        pub fn new_with_ca_with_snapshot(
            is_server: bool,
            crypto: Arc<RwLock<CryptoContext>>,
            verify_peer: bool,
            version: u32,
            version_information_parameter: &[u8],
            client_ca_path: Option<&str>,
            environment: &crate::env_utils::EnvSnapshot,
        ) -> Result<Self, ConnectionError> {
            Self::new_with_ca_with_snapshot_and_clock(
                is_server,
                crypto,
                verify_peer,
                version,
                version_information_parameter,
                client_ca_path,
                environment,
                &crate::time_source::ProtocolClock::default(),
            )
        }

        #[allow(clippy::too_many_arguments)]
        pub fn new_with_ca_with_snapshot_and_clock(
            is_server: bool,
            crypto: Arc<RwLock<CryptoContext>>,
            verify_peer: bool,
            version: u32,
            version_information_parameter: &[u8],
            client_ca_path: Option<&str>,
            environment: &crate::env_utils::EnvSnapshot,
            clock: &crate::time_source::ProtocolClock,
        ) -> Result<Self, ConnectionError> {
            let quic_version = Self::map_quic_version(version)?;
            let mut transport_params = Self::default_transport_params();
            transport_params.extend_from_slice(version_information_parameter);
            let client_ca_path = client_ca_path.map(str::to_owned);
            let connection = if is_server {
                Self::create_server_connection(quic_version, transport_params.clone())?
            } else {
                Self::create_client_connection(
                    verify_peer,
                    quic_version,
                    transport_params.clone(),
                    client_ca_path.as_deref(),
                    environment,
                )?
            };
            let this = Self {
                connection,
                clock: clock.clone(),
                crypto,
                is_server,
                #[cfg(debug_assertions)]
                environment: Arc::new(environment.clone()),
                #[cfg(debug_assertions)]
                verify_peer,
                client_ca_path,
                handshake_complete: false,
                write_level: super::Level::Initial,
                alpn: None,
                peer_cert: None,
                zero_rtt_enabled: false,
                transport_params,
                quic_version,
                peer_transport_params: None,
                profile: None,
                profile_ready_at: None,
                next_1rtt_secrets: None,
                pending_local_1rtt: VecDeque::new(),
                pending_remote_1rtt: VecDeque::new(),
                crypto_buffer: Vec::with_capacity(4096),
                frame_buffer: Vec::new(),
                session_cache: Some(Arc::new(RwLock::new(SessionCache::new(100)))),
                handshake_start: clock.now(),
                bytes_sent: 0,
                bytes_received: 0,
            };

            Ok(this)
        }

        fn map_quic_version(version: u32) -> Result<rustls::quic::Version, ConnectionError> {
            match version {
                PROTOCOL_VERSION => Ok(rustls::quic::Version::V1),
                PROTOCOL_VERSION_V2 => Ok(rustls::quic::Version::V2),
                _ => Err(ConnectionError::VersionMismatch),
            }
        }

        fn queue_crypto_bytes(
            &mut self,
            level: super::Level,
            data: &[u8],
        ) -> Result<(), ConnectionError> {
            if data.is_empty() {
                return Ok(());
            }
            let mut crypto = self.crypto.write();
            let result = match level {
                super::Level::Initial => crypto.crypto_initial.send(data),
                super::Level::Handshake => crypto.crypto_handshake.send(data),
                _ => crypto.crypto_application.send(data),
            };
            result?;
            self.bytes_sent = self.bytes_sent.saturating_add(data.len());
            Ok(())
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
            if let Some(ready_at) = self.profile_ready_at {
                if self.clock.now() < ready_at {
                    return Ok(());
                }
                self.profile_ready_at = None;
            }
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
                    self.queue_crypto_bytes(level, &pending)?;
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
            crypto.seal_1rtt = Some(Arc::new(crate::crypto::PacketAeadSeal::dynamic(Box::new(
                RustlsPacketSeal { key: local_pkt.clone() },
            ))));
            crypto.open_1rtt = Some(Arc::new(crate::crypto::PacketAeadOpen::dynamic(Box::new(
                RustlsPacketOpen { key: remote_pkt.clone() },
            ))));
            crypto.hp_1rtt = Some(Arc::new(RustlsHp { key: local_hp.clone() }));
            crypto.hp_1rtt_open = Some(Arc::new(RustlsHp { key: remote_hp.clone() }));
            self.pending_local_1rtt.clear();
            self.pending_remote_1rtt.clear();
            Ok(())
        }

        /// Build the client root certificate store: native/webpki roots plus any CA
        /// supplied by the owning transport configuration.
        fn build_client_root_store(
            ca_path: Option<&str>,
        ) -> Result<RootCertStore, ConnectionError> {
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
            // Load the client-scoped CA bundle if configured.
            if let Some(ca_path) = ca_path {
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
                if ca_certs.is_empty() {
                    return Err(ConnectionError::TlsError(format!(
                        "CA file parse failed ({}): no certificates found",
                        ca_path
                    )));
                }
                for cert in ca_certs {
                    roots.add(cert).map_err(|e| {
                        ConnectionError::TlsError(format!("Failed to add CA cert: {}", e))
                    })?;
                }
                log::info!("Loaded client-scoped CA certificates: {}", ca_path);
            }
            Ok(roots)
        }

        fn create_client_connection(
            verify_peer: bool,
            quic_version: rustls::quic::Version,
            transport_params: Vec<u8>,
            ca_path: Option<&str>,
            environment: &crate::env_utils::EnvSnapshot,
        ) -> Result<rustls::quic::Connection, ConnectionError> {
            #[cfg(not(debug_assertions))]
            let _ = verify_peer;
            #[cfg(not(debug_assertions))]
            let _ = environment;
            let roots = Self::build_client_root_store(ca_path)?;

            let builder =
                ClientConfig::builder_with_provider(Arc::new(crypto_provider_without_chacha()))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| {
                        ConnectionError::TlsError(format!("Protocol version error: {}", e))
                    })?;
            #[cfg(debug_assertions)]
            let allow_invalid =
                !verify_peer || environment.flag("QUICFUSCATE_ALLOW_INVALID_CERTS", false);
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

            let config =
                ServerConfig::builder_with_provider(Arc::new(crypto_provider_without_chacha()))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| {
                        ConnectionError::TlsError(format!("Protocol version error: {}", e))
                    })?
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
            // Store profile and schedule cosmetic timing without blocking the
            // caller. The synchronous provider API cannot await, so the
            // handshake I/O flush observes this deadline instead.
            self.profile = Some(profile.clone());
            let profile_ready_at = if profile.cover_performance_mode {
                None
            } else if let Some(jitter) = profile.timing_jitter {
                match self.clock.checked_deadline_after(jitter) {
                    Some(ready_at) => Some(ready_at),
                    None => {
                        log::warn!(
                            "TLS profile timing jitter deadline overflowed; continuing immediately"
                        );
                        None
                    }
                }
            } else {
                None
            };
            // Best-effort reconfigure only for client side before handshake
            if let rustls::quic::Connection::Client(_) = &self.connection {
                self.rebuild_client_connection(profile)?;
            }
            self.profile_ready_at = profile_ready_at;
            Ok(())
        }

        fn rebuild_client_connection(
            &mut self,
            profile: &TlsProfile,
        ) -> Result<(), ConnectionError> {
            // Build a fresh ClientConfig with ALPN and early data settings based on profile.
            // Use the same client-scoped root store so the configured CA remains effective
            // after a profile or SNI rebuild.
            let roots = Self::build_client_root_store(self.client_ca_path.as_deref())?;
            let builder =
                ClientConfig::builder_with_provider(Arc::new(crypto_provider_without_chacha()))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .map_err(|e| {
                        ConnectionError::TlsError(format!("Protocol version error: {}", e))
                    })?;
            #[cfg(debug_assertions)]
            let allow_invalid = !self.verify_peer
                || self.environment.flag("QUICFUSCATE_ALLOW_INVALID_CERTS", false);
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
            self.handshake_start = self.clock.now();
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

    impl crate::crypto::aead::PacketHeaderProtector for RustlsHp {
        fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], ConnectionError> {
            let sample_len = self.key.sample_len();
            if sample.len() != sample_len {
                super::trace_hp_error(&format!(
                    "hp sample length invalid have={} need={}",
                    sample.len(),
                    sample_len
                ));
                return Err(ConnectionError::CryptoError(format!(
                    "header protection sample must be exactly {sample_len} bytes, got {}",
                    sample.len()
                )));
            }

            // Derive the mask bytes by running HP on a controlled header snapshot.
            // We only need the low 5 bits of mask[0] (short header) and the next 4 bytes.
            // Force a 4-byte PN field in the HP helper call. Some implementations derive how many
            // PN bytes to mask from the low bits of `first`, so we set them to 3 (pn_len = 4).
            let first_orig: u8 = QUIC_FIXED_BIT | 0x03;
            let mut first: u8 = first_orig;
            let mut pn = [0u8; 4];
            if self.key.encrypt_in_place(sample, &mut first, &mut pn).is_err() {
                super::trace_hp_error("hp encrypt_in_place error");
                return Err(ConnectionError::CryptoError(
                    "header protection mask derivation failed".into(),
                ));
            }
            let mask0 = first ^ first_orig;
            super::trace_hp_mask(mask0, pn);
            Ok([mask0, pn[0], pn[1], pn[2], pn[3]])
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
        fn next_crypto_frame(
            &mut self,
            level: Level,
            max_len: usize,
        ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
            self.flush_handshake_io()?;
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
                let duration = self.clock.elapsed_since(self.handshake_start);
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
                        // Derive a stable session ticket hint from the peer certificate and ALPN.
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
                            let data = SessionData { ticket, timestamp: self.clock.now() };
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
        ) -> Result<SensitiveKeyingMaterial, ConnectionError> {
            if length == 0 {
                return Err(ConnectionError::TlsError(
                    "export_keying_material requires non-zero length".to_string(),
                ));
            }
            let output = SensitiveKeyingMaterial::new(vec![0u8; length]);
            self.connection
                .export_keying_material(
                    output,
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
            if self.crypto.write().key_update_1rtt_read()? {
                return Ok(());
            }
            self.update_read_from_rustls_chain()
        }
        fn key_update_write(&mut self) -> Result<(), ConnectionError> {
            self.ensure_1rtt_ready()?;
            if self.crypto.write().key_update_1rtt_write()? {
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

    #[allow(dead_code)]
    pub(super) fn make_with_ca_with_snapshot(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<RustlsProviderImpl, ConnectionError> {
        RustlsProviderImpl::new_with_ca_with_snapshot_and_clock(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            environment,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn make_with_ca_with_snapshot_and_clock(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<RustlsProviderImpl, ConnectionError> {
        RustlsProviderImpl::new_with_ca_with_snapshot_and_clock(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            environment,
            clock,
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
        Self::new_with_ca(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            None,
        )
    }

    fn new_with_ca(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
    ) -> Result<Self, ConnectionError> {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_ca_with_snapshot(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            &environment,
        )
    }

    fn new_with_ca_with_snapshot(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca_with_snapshot_and_clock(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            environment,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_ca_with_snapshot_and_clock(
        is_server: bool,
        crypto: Arc<RwLock<CryptoContext>>,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<Self, ConnectionError> {
        Ok(Self(rustls_provider::make_with_ca_with_snapshot_and_clock(
            is_server,
            crypto,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            environment,
            clock,
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
    fn next_crypto_frame(
        &mut self,
        level: Level,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
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
    ) -> Result<SensitiveKeyingMaterial, ConnectionError> {
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
