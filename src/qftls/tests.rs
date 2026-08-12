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

    let output =
        std::process::Command::new(std::env::current_exe().expect("resolve qftls test executable"))
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

#[cfg(unix)]
#[test]
fn individually_locked_key_mappings_are_page_exclusive() {
    let first = MappedKeyMaterial::new(Zeroizing::new(vec![0x31; 512]))
        .expect("allocate first page-exclusive key mapping");
    let second = MappedKeyMaterial::new(Zeroizing::new(vec![0x42; 512]))
        .expect("allocate second page-exclusive key mapping");
    // SAFETY: sysconf accepts the documented _SC_PAGESIZE selector and has
    // no pointer arguments or retained ownership.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };

    assert!(page_size > 0, "Unix page size must be positive");
    let page_size = usize::try_from(page_size).expect("positive page size fits usize");
    assert_eq!(first.ptr.addr() % page_size, 0);
    assert_eq!(second.ptr.addr() % page_size, 0);
    assert_ne!(first.ptr.addr(), second.ptr.addr());
    assert!(first.as_slice().iter().all(|byte| *byte == 0x31));
    assert!(second.as_slice().iter().all(|byte| *byte == 0x42));
}

#[cfg(unix)]
fn native_locked_identity(cert: &[u8], key: &[u8]) -> PreloadedServerIdentity {
    let mapped = MappedKeyMaterial::new(Zeroizing::new(key.to_vec()))
        .expect("allocate page-exclusive native key mapping");
    assert_eq!(mapped.status(), TlsKeyLockStatus::Locked);
    PreloadedServerIdentity {
        cert_pem: cert.to_vec(),
        key_pem: LockedKeyMaterial {
            status: mapped.status(),
            storage: KeyMaterialStorage::Mapped(mapped),
        },
    }
}

#[cfg(unix)]
#[test]
#[ignore = "requires a native Unix mlock budget and runs in dedicated CI steps"]
fn native_rejected_preload_values_release_only_their_own_key_mapping() {
    let _ = take_key_unlock_observations();
    let slot = OnceLock::new();
    let accepted = native_locked_identity(b"accepted-cert", b"accepted-key");
    assert!(matches!(
        publish_preloaded_identity(&slot, accepted),
        Ok(TlsIdentityPreloadStatus::Loaded { key_lock: TlsKeyLockStatus::Locked })
    ));

    let duplicate = native_locked_identity(b"accepted-cert", b"accepted-key");
    assert_eq!(
        publish_preloaded_identity(&slot, duplicate),
        Ok(TlsIdentityPreloadStatus::AlreadyLoaded)
    );
    let conflict = native_locked_identity(b"conflict-cert", b"conflict-key");
    assert!(publish_preloaded_identity(&slot, conflict).is_err());

    let accepted_bytes =
        slot.get().expect("accepted identity remains published").key_pem.as_slice();
    assert_eq!(accepted_bytes, b"accepted-key");
    assert_eq!(take_key_unlock_observations(), vec![(true, true), (true, true)]);

    drop(slot);
    assert_eq!(take_key_unlock_observations(), vec![(true, true)]);
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
    let information = VersionInformation {
        chosen: PROTOCOL_VERSION_V2,
        available: vec![PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
    }
    .encode_parameter()
    .unwrap();
    let provider = create_provider_for_version(false, false, PROTOCOL_VERSION_V2, &information)
        .expect("create v2 provider");
    assert!(provider.get_quic_transport_params().ends_with(&information));
}

#[test]
fn rustls_client_hello_policy_excludes_chacha_for_chrome_and_firefox() {
    let mut provider =
        RustlsProvider::new(false, false, PROTOCOL_VERSION, &[]).expect("client provider");

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
        profile.extension_order.iter().all(|extension| known_chrome_extensions.contains(extension)),
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
    let provider = create_provider(false).unwrap();

    assert!(provider.provider_name().starts_with("rustls"));
}

#[test]
fn tls_cover_support_matches_provider_name() {
    let cover_enabled = std::env::var("QUICFUSCATE_TLS_COVER")
        .map(|raw| raw != "0" && !raw.eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    let provider = create_provider(false).unwrap();

    assert!(!provider.supports_ch_override());
    assert_eq!(provider.provider_name() == "rustls+tls-cover", cover_enabled);
}

#[test]
fn test_profile_chrome_has_h3_alpn() {
    let p = TlsProfile::chrome_130();
    assert!(p.alpn_protocols.iter().any(|a| a == "h3"), "Chrome profile must include h3 in ALPN");
}

#[test]
fn test_profile_firefox_has_h3_alpn() {
    let p = TlsProfile::firefox_133();
    assert!(p.alpn_protocols.iter().any(|a| a == "h3"), "Firefox profile must include h3 in ALPN");
}

#[test]
fn test_profile_safari_has_h3_alpn() {
    let p = TlsProfile::safari_18();
    assert!(p.alpn_protocols.iter().any(|a| a == "h3"), "Safari profile must include h3 in ALPN");
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
