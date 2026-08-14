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

fn client_hello_extensions(frame: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let body_len = usize::try_from(u32::from_be_bytes([0, frame[1], frame[2], frame[3]]))
        .expect("ClientHello body length");
    let body = &frame[4..4 + body_len];
    let session_id_end = 35 + usize::from(body[34]);
    let suites_len =
        usize::from(u16::from_be_bytes([body[session_id_end], body[session_id_end + 1]]));
    let suites_end = session_id_end + 2 + suites_len;
    let compression_end = suites_end + 1 + usize::from(body[suites_end]);
    let extensions_len =
        usize::from(u16::from_be_bytes([body[compression_end], body[compression_end + 1]]));
    let mut offset = compression_end + 2;
    let extensions_end = offset + extensions_len;
    assert!(extensions_end <= body.len(), "ClientHello extensions are truncated");

    let mut extensions = Vec::new();
    while offset < extensions_end {
        assert!(offset + 4 <= extensions_end, "ClientHello extension header is truncated");
        let extension_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let extension_len = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        offset += 4;
        let extension_end = offset + extension_len;
        assert!(extension_end <= extensions_end, "ClientHello extension body is truncated");
        extensions.push((extension_type, body[offset..extension_end].to_vec()));
        offset = extension_end;
    }
    extensions
}

fn client_hello_extension(extensions: &[(u16, Vec<u8>)], extension_type: u16) -> &[u8] {
    extensions
        .iter()
        .find_map(|(kind, data)| (*kind == extension_type).then_some(data.as_slice()))
        .expect("required ClientHello extension")
}

fn client_hello_sni(extension: &[u8]) -> String {
    assert!(extension.len() >= 5, "SNI extension is truncated");
    assert_eq!(extension[2], 0, "first SNI entry must be a DNS hostname");
    let name_len = usize::from(u16::from_be_bytes([extension[3], extension[4]]));
    String::from_utf8(extension[5..5 + name_len].to_vec()).expect("SNI hostname is UTF-8")
}

fn client_hello_alpn(extension: &[u8]) -> Vec<String> {
    let mut offset = 2usize;
    let mut protocols = Vec::new();
    while offset < extension.len() {
        let protocol_len = usize::from(extension[offset]);
        offset += 1;
        let protocol_end = offset + protocol_len;
        protocols.push(
            String::from_utf8(extension[offset..protocol_end].to_vec())
                .expect("ALPN protocol is UTF-8"),
        );
        offset = protocol_end;
    }
    protocols
}

fn client_hello_supported_versions(extension: &[u8]) -> Vec<u16> {
    extension[1..1 + usize::from(extension[0])]
        .chunks_exact(2)
        .map(|version| u16::from_be_bytes([version[0], version[1]]))
        .collect()
}

fn client_hello_key_share_groups(extension: &[u8]) -> Vec<u16> {
    let mut offset = 2usize;
    let mut groups = Vec::new();
    while offset < extension.len() {
        let group = u16::from_be_bytes([extension[offset], extension[offset + 1]]);
        let key_len =
            usize::from(u16::from_be_bytes([extension[offset + 2], extension[offset + 3]]));
        groups.push(group);
        offset += 4 + key_len;
    }
    groups
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
fn every_supported_persona_controls_the_real_rustls_client_hello_order() {
    let mut provider =
        RustlsProvider::new(false, false, PROTOCOL_VERSION, &[]).expect("client provider");

    for mut profile in [
        TlsProfile::chrome_130(),
        TlsProfile::firefox_133(),
        TlsProfile::safari_18(),
        TlsProfile::edge_130(),
        TlsProfile::opera_115(),
        TlsProfile::brave_1_73(),
    ] {
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
        let expected = profile
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| matches!(*suite, 0x1301 | 0x1302))
            .collect::<Vec<_>>();
        assert_eq!(suites, expected, "real rustls order must follow {}", profile.name);

        let extensions = client_hello_extensions(&frame);
        let mut extension_types = extensions.iter().map(|(kind, _)| *kind).collect::<Vec<_>>();
        let extension_count = extension_types.len();
        extension_types.sort_unstable();
        extension_types.dedup();
        assert_eq!(extension_types.len(), extension_count, "duplicate real extension");
        assert_eq!(
            client_hello_sni(client_hello_extension(&extensions, 0x0000)),
            DEFAULT_TLS_SNI_HOST
        );
        assert_eq!(
            client_hello_alpn(client_hello_extension(&extensions, 0x0010)),
            profile.alpn_protocols
        );
        assert_eq!(
            client_hello_supported_versions(client_hello_extension(&extensions, 0x002b)),
            vec![0x0304]
        );
        let key_share_groups =
            client_hello_key_share_groups(client_hello_extension(&extensions, 0x0033));
        assert!(!key_share_groups.is_empty(), "real ClientHello has no key share");
        assert!(
            key_share_groups.iter().any(|group| profile.groups.contains(group)),
            "real ClientHello key shares do not overlap {}",
            profile.name
        );
    }
}

#[test]
fn real_provider_rejects_every_0rtt_activation_path() {
    set_max_early_data_size(u32::MAX);
    let mut client =
        RustlsProvider::new(false, false, PROTOCOL_VERSION, &[]).expect("client provider");
    assert!(client.enable_0rtt().is_err());
    assert!(client.get_0rtt_keys().is_none());

    let mut profile = TlsProfile::chrome_130();
    profile.timing_jitter = None;
    profile.enable_0rtt = true;
    let error = client.configure(&profile).expect_err("profile 0-RTT must fail closed");
    assert!(error.to_string().contains("0-RTT is disabled"));

    let defaults = [
        TlsProfile::chrome_130(),
        TlsProfile::firefox_133(),
        TlsProfile::safari_18(),
        TlsProfile::edge_130(),
        TlsProfile::opera_115(),
        TlsProfile::brave_1_73(),
    ];
    assert!(defaults.iter().all(|profile| !profile.enable_0rtt));
}

#[test]
fn rustls_client_hello_uses_profile_order_and_rejects_empty_overlap() {
    let mut provider =
        RustlsProvider::new(false, false, PROTOCOL_VERSION, &[]).expect("client provider");
    let mut reverse = TlsProfile::chrome_130();
    reverse.timing_jitter = None;
    reverse.cipher_suites = vec![0x1302, 0x1301, 0x1302, 0xc02f];
    provider.configure(&reverse).expect("reverse suite profile");
    let (_, frame) = provider
        .next_crypto_frame(Level::Initial, usize::MAX)
        .expect("next initial frame")
        .expect("initial ClientHello");
    assert_eq!(client_hello_cipher_suites(&frame), vec![0x1302, 0x1301]);

    let mut unsupported = TlsProfile::chrome_130();
    unsupported.cipher_suites = vec![0x1303, 0xc02f, 0xdead];
    let error = provider.configure(&unsupported).expect_err("empty overlap must fail closed");
    assert!(error.to_string().contains("no supported TLS 1.3 AES-GCM cipher suite"));
}

fn transfer_tls_crypto(
    source: &mut RustlsProvider,
    destination: &mut RustlsProvider,
) -> Result<usize, ConnectionError> {
    let mut transferred = 0usize;
    for level in [Level::Initial, Level::Handshake, Level::Application] {
        while let Some((_offset, bytes)) = source.next_crypto_frame(level, usize::MAX)? {
            transferred = transferred.saturating_add(bytes.len());
            destination.provide_quic_data(level, &bytes)?;
        }
    }
    Ok(transferred)
}

fn assert_live_rustls_handshake(mut profile: TlsProfile, expected_suite: StandardCipherSuite) {
    use crate::crypto::aead::{AeadOpen, AeadSeal};
    use crate::qftls::rustls_provider::{take_standard_packet_operations, StandardPacketOperation};

    let _ = take_standard_packet_operations();
    let mut client =
        RustlsProvider::new(false, false, PROTOCOL_VERSION, &[]).expect("client provider");
    let mut server =
        RustlsProvider::new(true, false, PROTOCOL_VERSION, &[]).expect("server provider");
    let client_keys = parking_lot::RwLock::new(crate::transport::packet::CryptoContext::default());
    let server_keys = parking_lot::RwLock::new(crate::transport::packet::CryptoContext::default());

    profile.timing_jitter = None;
    profile.sni = Some("localhost".to_string());
    profile.enable_0rtt = false;
    profile.cipher_suites = vec![expected_suite.tls_id()];
    client.configure(&profile).expect("configure client profile");

    for _ in 0..64 {
        client.poll_secrets_and_install(&client_keys).expect("poll client keys");
        server.poll_secrets_and_install(&server_keys).expect("poll server keys");
        let client_bytes = transfer_tls_crypto(&mut client, &mut server).expect("client flight");
        let server_bytes = transfer_tls_crypto(&mut server, &mut client).expect("server flight");
        client.poll_secrets_and_install(&client_keys).expect("install client keys");
        server.poll_secrets_and_install(&server_keys).expect("install server keys");
        if client.handshake_complete() && server.handshake_complete() {
            break;
        }
        assert_ne!(
            client_bytes + server_bytes,
            0,
            "live handshake stalled before both endpoints completed"
        );
    }

    assert!(client.handshake_complete());
    assert!(server.handshake_complete());
    for snapshot in [
        client_keys.read().packet_protection_snapshot(),
        server_keys.read().packet_protection_snapshot(),
    ] {
        assert_eq!(snapshot.negotiated_tls_cipher_suite, Some(expected_suite));
        assert_eq!(snapshot.handshake.packet_aead_owner, PacketProtectionOwner::RustlsStandard);
        assert_eq!(
            snapshot.handshake.header_protection_owner,
            PacketProtectionOwner::RustlsStandard
        );
        assert_eq!(snapshot.one_rtt.packet_aead_owner, PacketProtectionOwner::RustlsStandard);
        assert_eq!(snapshot.one_rtt.header_protection_owner, PacketProtectionOwner::RustlsStandard);
        assert_eq!(snapshot.zero_rtt.packet_aead_owner, PacketProtectionOwner::Disabled);
    }

    let client_seal = client_keys.read().seal_1rtt.clone().expect("client rustls seal owner");
    let server_open = server_keys.read().open_1rtt.clone().expect("server rustls open owner");
    let plaintext = b"runtime-owner-proof";
    let mut packet = vec![0u8; plaintext.len() + 16];
    packet[..plaintext.len()].copy_from_slice(plaintext);
    let sealed = client_seal
        .seal_with_u64_counter(7, b"authenticated-header", &mut packet, plaintext.len(), None)
        .expect("seal with installed rustls key");
    assert_eq!(sealed, packet.len());
    let opened = server_open
        .open_with_u64_counter(7, b"authenticated-header", &mut packet)
        .expect("open with installed rustls key");
    assert_eq!(&packet[..opened], plaintext);

    client.key_update_write(&client_keys).expect("client rustls write-key update");
    server.key_update_read(&server_keys).expect("server rustls read-key update");
    let client_seal = client_keys.read().seal_1rtt.clone().expect("updated client seal owner");
    let server_open = server_keys.read().open_1rtt.clone().expect("updated server open owner");
    packet[..plaintext.len()].copy_from_slice(plaintext);
    client_seal
        .seal_with_u64_counter(8, b"authenticated-header", &mut packet, plaintext.len(), None)
        .expect("seal with updated rustls key");
    let opened = server_open
        .open_with_u64_counter(8, b"authenticated-header", &mut packet)
        .expect("open with updated rustls key");
    assert_eq!(&packet[..opened], plaintext);
    assert_eq!(
        client_keys.read().packet_protection_snapshot().one_rtt.packet_aead_owner,
        PacketProtectionOwner::RustlsStandard
    );
    assert_eq!(
        take_standard_packet_operations(),
        vec![
            StandardPacketOperation::Seal,
            StandardPacketOperation::Open,
            StandardPacketOperation::Seal,
            StandardPacketOperation::Open,
        ]
    );
}

#[test]
fn every_supported_persona_completes_real_standard_suite_handshakes() {
    for profile in [
        TlsProfile::chrome_130(),
        TlsProfile::firefox_133(),
        TlsProfile::safari_18(),
        TlsProfile::edge_130(),
        TlsProfile::opera_115(),
        TlsProfile::brave_1_73(),
    ] {
        for suite in [StandardCipherSuite::Aes128GcmSha256, StandardCipherSuite::Aes256GcmSha384] {
            assert_live_rustls_handshake(profile.clone(), suite);
        }
    }
}

#[test]
fn rustls_ticket_resumption_is_reported_without_0rtt_keys() {
    static TEST_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let sni = format!(
        "resumption-{}-{}.example",
        std::process::id(),
        TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut profile = TlsProfile::chrome_130();
    profile.timing_jitter = None;
    profile.sni = Some(sni);
    profile.cipher_suites = vec![StandardCipherSuite::Aes128GcmSha256.tls_id()];
    profile.enable_0rtt = false;

    let mut first_client =
        RustlsProvider::new(false, false, PROTOCOL_VERSION, &[]).expect("first client provider");
    let mut first_server =
        RustlsProvider::new(true, false, PROTOCOL_VERSION, &[]).expect("first server provider");
    let first_client_keys =
        parking_lot::RwLock::new(crate::transport::packet::CryptoContext::default());
    let first_server_keys =
        parking_lot::RwLock::new(crate::transport::packet::CryptoContext::default());
    first_client.configure(&profile).expect("configure first client");

    for _ in 0..64 {
        first_client.poll_secrets_and_install(&first_client_keys).expect("poll first client keys");
        first_server.poll_secrets_and_install(&first_server_keys).expect("poll first server keys");
        let transferred = transfer_tls_crypto(&mut first_client, &mut first_server)
            .expect("first client flight")
            + transfer_tls_crypto(&mut first_server, &mut first_client)
                .expect("first server flight");
        first_client
            .poll_secrets_and_install(&first_client_keys)
            .expect("install first client keys");
        first_server
            .poll_secrets_and_install(&first_server_keys)
            .expect("install first server keys");
        if first_client.handshake_complete() && first_server.handshake_complete() {
            break;
        }
        assert_ne!(transferred, 0, "first resumption baseline handshake stalled");
    }
    assert!(first_client.handshake_complete() && first_server.handshake_complete());
    assert!(!first_client.handshake_resumed());
    assert!(!first_server.handshake_resumed());

    let mut resumed_client =
        RustlsProvider::new(false, false, PROTOCOL_VERSION, &[]).expect("resumed client provider");
    let mut resumed_server =
        RustlsProvider::new(true, false, PROTOCOL_VERSION, &[]).expect("resumed server provider");
    let resumed_client_keys =
        parking_lot::RwLock::new(crate::transport::packet::CryptoContext::default());
    let resumed_server_keys =
        parking_lot::RwLock::new(crate::transport::packet::CryptoContext::default());
    resumed_client.configure(&profile).expect("configure resumed client");

    for _ in 0..64 {
        resumed_client
            .poll_secrets_and_install(&resumed_client_keys)
            .expect("poll resumed client keys");
        resumed_server
            .poll_secrets_and_install(&resumed_server_keys)
            .expect("poll resumed server keys");
        let transferred = transfer_tls_crypto(&mut resumed_client, &mut resumed_server)
            .expect("resumed client flight")
            + transfer_tls_crypto(&mut resumed_server, &mut resumed_client)
                .expect("resumed server flight");
        resumed_client
            .poll_secrets_and_install(&resumed_client_keys)
            .expect("install resumed client keys");
        resumed_server
            .poll_secrets_and_install(&resumed_server_keys)
            .expect("install resumed server keys");
        if resumed_client.handshake_complete() && resumed_server.handshake_complete() {
            break;
        }
        assert_ne!(transferred, 0, "TLS ticket resumption handshake stalled");
    }

    assert!(resumed_client.handshake_complete() && resumed_server.handshake_complete());
    assert!(resumed_client.handshake_resumed(), "client must report TLS 1.3 resumption");
    assert!(resumed_server.handshake_resumed(), "server must report TLS 1.3 resumption");
    assert!(resumed_client.get_0rtt_keys().is_none());
    assert!(resumed_server.get_0rtt_keys().is_none());
    assert!(resumed_client.session_ticket().is_none());
    assert!(resumed_server.session_ticket().is_none());
    for snapshot in [
        resumed_client_keys.read().packet_protection_snapshot(),
        resumed_server_keys.read().packet_protection_snapshot(),
    ] {
        assert_eq!(
            snapshot.negotiated_tls_cipher_suite,
            Some(StandardCipherSuite::Aes128GcmSha256)
        );
        assert_eq!(snapshot.zero_rtt.packet_aead_owner, PacketProtectionOwner::Disabled);
        assert_eq!(snapshot.one_rtt.packet_aead_owner, PacketProtectionOwner::RustlsStandard);
        assert_eq!(snapshot.one_rtt.header_protection_owner, PacketProtectionOwner::RustlsStandard);
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
