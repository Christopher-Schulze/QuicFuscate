use super::*;

use qf_stealth::transport_params::{
    decode_transport_params, transport_param_fixture, EngineFamily, HandshakeConnectionIds,
};

fn decode_varint_value(bytes: &[u8]) -> u64 {
    let (value, len) =
        qf_stealth::transport_params::read_varint(bytes).expect("varint value must decode");
    assert_eq!(len, bytes.len());
    value
}

/// framed version_information used across the fixture tests:
/// id=0x11, len=8, chosen=1, available=[1].
const TEST_VERSION_INFORMATION: &[u8] =
    &[0x11, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];

fn name_to_id(name: &str) -> Option<u64> {
    Some(match name {
        "max_idle_timeout" => 0x01,
        "max_udp_payload_size" => 0x03,
        "initial_max_data" => 0x04,
        "initial_max_stream_data_bidi_local" => 0x05,
        "initial_max_stream_data_bidi_remote" => 0x06,
        "initial_max_stream_data_uni" => 0x07,
        "initial_max_streams_bidi" => 0x08,
        "initial_max_streams_uni" => 0x09,
        "active_connection_id_limit" => 0x0e,
        "initial_source_connection_id" => 0x0f,
        "version_information" => 0x11,
        "reset_stream_at" => 0x1d,
        "max_datagram_frame_size" => 0x20,
        "grease_quic_bit" => 0x2ab2,
        "google_connection_options" => 0x3128,
        "max_ack_delay" => 0x0b,
        "min_ack_delay" => 0xff02_de1a,
        _ => return None,
    })
}

#[test]
fn fixture_transport_params_cap_udp_payload_at_path_budget() {
    let scid = [0xabu8; 8];
    let params = RustlsProviderImpl::fixture_transport_params(
        EngineFamily::Chromium,
        1413,
        &HandshakeConnectionIds::client(&scid),
        TEST_VERSION_INFORMATION,
    )
    .expect("custom UDP payload size must produce valid transport parameters");
    let decoded = decode_transport_params(&params);
    let udp =
        decoded.iter().find(|(id, _)| *id == 0x03).map(|(_, value)| decode_varint_value(value));
    // min(fixture cap 1472, path budget 1413)
    assert_eq!(udp, Some(1413));

    assert!(RustlsProviderImpl::fixture_transport_params(
        EngineFamily::Chromium,
        1199,
        &HandshakeConnectionIds::client(&scid),
        &[],
    )
    .is_err());
}

#[test]
fn provider_rejects_role_mismatches_and_oversized_handshake_cids() {
    let environment = crate::env_utils::EnvSnapshot::capture();
    let clock = crate::time_source::ProtocolClock::default();
    for (is_server, ids) in [
        (false, HandshakeConnectionIds::server(b"server", b"original", None)),
        (true, HandshakeConnectionIds::client(b"client")),
        (false, HandshakeConnectionIds::client(&[7; 21])),
        (true, HandshakeConnectionIds::server(b"server", &[7; 21], None)),
        (true, HandshakeConnectionIds::server(b"server", b"original", Some(&[7; 21]))),
    ] {
        assert!(RustlsProviderImpl::new_with_ca_with_snapshot_and_clock_and_max_udp_payload(
            is_server,
            false,
            PROTOCOL_VERSION,
            &[],
            None,
            &environment,
            &clock,
            1350,
            &ids,
            None,
            false,
        )
        .is_err());
    }
}

#[test]
fn chromium_transport_params_match_capture_fixture() {
    let fixture = transport_param_fixture(EngineFamily::Chromium);
    let scid = [0xabu8; 8];
    let params = RustlsProviderImpl::fixture_transport_params(
        EngineFamily::Chromium,
        1350,
        &HandshakeConnectionIds::client(&scid),
        TEST_VERSION_INFORMATION,
    )
    .expect("chromium fixture params");
    let decoded = decode_transport_params(&params);
    let ids: Vec<u64> = decoded.iter().map(|(id, _)| *id).collect();

    // Every numeric fixture parameter in `sends` is present with the
    // captured value, except the per-connection fields handled below.
    let decoded_map: std::collections::BTreeMap<u64, Vec<u8>> = decoded.iter().cloned().collect();
    for name in fixture.sends() {
        let Some(id) = name_to_id(name) else { continue };
        assert!(decoded_map.contains_key(&id), "fixture parameter '{name}' missing");
        if let Some(expected) = fixture.values().get(name.as_str()) {
            let actual = decode_varint_value(&decoded_map[&id]);
            let expected =
                if name == "max_udp_payload_size" { (*expected).min(1350) } else { *expected };
            assert_eq!(actual, expected, "fixture parameter '{name}' value drifted");
        }
    }
    // Real local SCID, never a constant.
    assert_eq!(decoded_map[&0x0f], scid.to_vec());
    // Chrome inserts exactly one GREASE transport parameter (31N+27 space;
    // 0x2ab2/0xff02de1a are reserved ids living in that space by design).
    let grease_ids: Vec<u64> = ids
        .iter()
        .copied()
        .filter(|id| id % 31 == 27 && !matches!(*id, 0x2ab2 | 0xff02_de1a))
        .collect();
    assert_eq!(grease_ids.len(), 1, "chromium must emit exactly one GREASE TP");
    // 'ORIG' google_connection_options is present.
    assert_eq!(decoded_map[&0x3128], b"ORIG".to_vec());
}

#[test]
fn firefox_transport_params_match_neqo_fixture_order_and_values() {
    let fixture = transport_param_fixture(EngineFamily::Firefox);
    let scid = [0xcdu8; 16];
    let params = RustlsProviderImpl::fixture_transport_params(
        EngineFamily::Firefox,
        1350,
        &HandshakeConnectionIds::client(&scid),
        TEST_VERSION_INFORMATION,
    )
    .expect("firefox fixture params");
    let decoded = decode_transport_params(&params);
    // neqo order is fixed: ids must appear exactly in fixture `sends` order.
    let expected_ids: Vec<u64> =
        fixture.sends().iter().filter_map(|name| name_to_id(name)).collect();
    let actual_ids: Vec<u64> = decoded.iter().map(|(id, _)| *id).collect();
    assert_eq!(actual_ids, expected_ids, "firefox TP order must match fixture");

    let decoded_map: std::collections::BTreeMap<u64, Vec<u8>> = decoded.iter().cloned().collect();
    for name in fixture.sends() {
        if let Some(expected) = fixture.values().get(name.as_str()) {
            let id = name_to_id(name).expect("mapped name");
            assert_eq!(
                decode_varint_value(&decoded_map[&id]),
                *expected,
                "firefox fixture parameter '{name}' value drifted"
            );
        }
    }
    assert_eq!(decoded_map[&0x0f], scid.to_vec());
    // neqo emits empty grease_quic_bit and reset_stream_at parameters.
    assert_eq!(decoded_map[&0x2ab2], Vec::<u8>::new());
    assert_eq!(decoded_map[&0x1d], Vec::<u8>::new());
}

#[test]
fn personas_do_not_share_parameter_structure() {
    let scid = [0xabu8; 8];
    let chrome_ids: std::collections::BTreeSet<u64> = decode_transport_params(
        &RustlsProviderImpl::fixture_transport_params(
            EngineFamily::Chromium,
            1350,
            &HandshakeConnectionIds::client(&scid),
            TEST_VERSION_INFORMATION,
        )
        .expect("chromium"),
    )
    .into_iter()
    .map(|(id, _)| id)
    .collect();
    let firefox_ids: std::collections::BTreeSet<u64> = decode_transport_params(
        &RustlsProviderImpl::fixture_transport_params(
            EngineFamily::Firefox,
            1350,
            &HandshakeConnectionIds::client(&scid),
            TEST_VERSION_INFORMATION,
        )
        .expect("firefox"),
    )
    .into_iter()
    .map(|(id, _)| id)
    .collect();
    assert_ne!(chrome_ids, firefox_ids, "distinct engines must emit distinct TP sets");
}

#[test]
fn grease_values_differ_per_connection() {
    let scid = [0xabu8; 8];
    let first = RustlsProviderImpl::fixture_transport_params(
        EngineFamily::Chromium,
        1350,
        &HandshakeConnectionIds::client(&scid),
        &[],
    )
    .expect("first");
    let second = RustlsProviderImpl::fixture_transport_params(
        EngineFamily::Chromium,
        1350,
        &HandshakeConnectionIds::client(&scid),
        &[],
    )
    .expect("second");
    let grease = |encoded: &[u8]| -> Vec<(u64, Vec<u8>)> {
        decode_transport_params(encoded)
            .into_iter()
            .filter(|(id, _)| id % 31 == 27 && !matches!(*id, 0x2ab2 | 0xff02_de1a))
            .collect()
    };
    let (g1, g2) = (grease(&first), grease(&second));
    assert_eq!(g1.len(), 1);
    assert_eq!(g2.len(), 1);
    // Real GREASE: id or value must differ across connections.
    assert!(g1[0].0 != g2[0].0 || g1[0].1 != g2[0].1, "GREASE must be per-connection");
}

#[test]
fn apply_profile_rebuilds_transport_params_from_persona_fixture() {
    let environment = crate::env_utils::EnvSnapshot::capture();
    let clock = crate::time_source::ProtocolClock::default();
    let scid = [0x42u8; 16];
    let mut provider = RustlsProviderImpl::new_with_ca_with_snapshot_and_clock_and_max_udp_payload(
        false,
        false,
        PROTOCOL_VERSION,
        &[],
        None,
        &environment,
        &clock,
        1350,
        &HandshakeConnectionIds::client(&scid),
        None,
        false,
    )
    .expect("client provider");

    let profile = TlsProfile::firefox_133();
    provider.apply_profile_to_config(&profile).expect("apply persona");

    let decoded: std::collections::BTreeMap<u64, Vec<u8>> =
        decode_transport_params(&provider.transport_params).into_iter().collect();
    let fixture = transport_param_fixture(EngineFamily::Firefox);
    let initial_max_data = decode_varint_value(&decoded[&0x04]);
    assert_eq!(initial_max_data, fixture.values()["initial_max_data"]);
    assert_eq!(decoded[&0x0f], scid.to_vec());
    // The fingerprint applied to the internal transport config reads from
    // the same fixture: advertised and internal values cannot drift.
    let fingerprint = qf_stealth::FingerprintProfile::new(
        qf_stealth::BrowserProfile::Firefox,
        qf_stealth::OsProfile::Linux,
    );
    assert_eq!(initial_max_data, fingerprint.initial_max_data);
}

mod profile_delay_tests {
    use super::*;
    use std::time::{Duration, Instant, SystemTime};

    fn provider_with_manual_clock() -> RustlsProviderImpl {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            Instant::now(),
            SystemTime::UNIX_EPOCH,
        );
        let clock = crate::time_source::ProtocolClock::from_source(source);
        let environment = crate::env_utils::EnvSnapshot::capture();
        RustlsProviderImpl::new_with_ca_with_snapshot_and_clock(
            false,
            false,
            PROTOCOL_VERSION,
            &[],
            None,
            &environment,
            &clock,
        )
        .expect("client provider")
    }

    #[test]
    fn profile_jitter_is_scheduled_without_blocking_configuration() {
        let mut provider = provider_with_manual_clock();
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

    #[test]
    fn handshake_readiness_deadline_surfaces_and_clears_profile_jitter() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            Instant::now(),
            SystemTime::UNIX_EPOCH,
        );
        let clock = crate::time_source::ProtocolClock::from_source(source.clone());
        let environment = crate::env_utils::EnvSnapshot::capture();
        let mut provider = RustlsProviderImpl::new_with_ca_with_snapshot_and_clock(
            false,
            false,
            PROTOCOL_VERSION,
            &[],
            None,
            &environment,
            &clock,
        )
        .expect("client provider");
        let mut profile = TlsProfile::chrome_130();
        profile.timing_jitter = Some(Duration::from_secs(2));
        provider.apply_profile_to_config(&profile).expect("profile configuration");

        let ready_at = provider
            .handshake_send_ready_at()
            .expect("armed profile jitter must surface a readiness deadline");
        assert!(ready_at > clock.now());
        assert!(provider
            .next_crypto_frame(Level::Initial, usize::MAX)
            .expect("deferred frame poll")
            .is_none());

        // Once the readiness deadline passes, the deferred ClientHello is
        // emitted and the gate clears - a zero-byte send poll is a retry
        // signal, never a dead end.
        source.advance(Duration::from_secs(3));
        assert!(provider
            .next_crypto_frame(Level::Initial, usize::MAX)
            .expect("post-deadline frame poll")
            .is_some());
        assert_eq!(provider.handshake_send_ready_at(), None);
    }

    #[test]
    fn provider_owned_crypto_range_requeues_and_retires_exact_bytes() {
        let mut provider = provider_with_manual_clock();
        let mut profile = TlsProfile::chrome_130();
        profile.timing_jitter = Some(Duration::from_secs(2));
        provider.apply_profile_to_config(&profile).expect("profile configuration");
        provider.crypto_initial.send(b"client-hello-range").expect("queue CRYPTO range");

        assert!(provider.has_pending_handshake_send());
        let (offset, first) = provider
            .next_crypto_frame(Level::Initial, usize::MAX)
            .expect("take CRYPTO range")
            .expect("queued CRYPTO range");
        assert_eq!((offset, first.as_slice()), (0, b"client-hello-range".as_slice()));
        assert!(!provider.has_pending_handshake_send());

        provider
            .requeue_crypto(Level::Initial, offset, first.len() as u64)
            .expect("requeue lost CRYPTO range");
        let retransmission = provider
            .next_crypto_frame(Level::Initial, usize::MAX)
            .expect("take retransmission")
            .expect("queued retransmission");
        assert_eq!(retransmission, (offset, first.clone()));

        provider
            .ack_crypto(Level::Initial, offset, first.len() as u64)
            .expect("retire acknowledged CRYPTO range");
        provider.requeue_all_crypto(Level::Initial);
        assert!(provider
            .next_crypto_frame(Level::Initial, usize::MAX)
            .expect("probe retired range")
            .is_none());
    }

    #[test]
    fn rustls_output_waits_for_crypto_queue_and_retention_capacity() {
        let mut provider = provider_with_manual_clock();
        let limit = qf_transport_crypto_stream::MAX_CRYPTO_BUFFERED_BYTES;
        let filler = vec![0xA5; limit];
        provider.crypto_initial.send(&filler).expect("fill unsent CRYPTO queue");

        provider.flush_handshake_io().expect("defer rustls output without losing it");
        assert_eq!(provider.pending_crypto_level, Some(Level::Initial));
        assert!(provider.has_pending_handshake_send());
        let held_client_hello = provider.crypto_buffer.clone();
        assert!(!held_client_hello.is_empty());
        for _ in 0..3 {
            provider.flush_handshake_io().expect("retain blocked rustls output");
            assert_eq!(provider.crypto_buffer, held_client_hello);
            assert_eq!(provider.pending_crypto_level, Some(Level::Initial));
            assert_eq!(provider.bytes_sent, 0);
        }

        let (offset, sent) = provider
            .crypto_initial
            .next_crypto_frame(limit)
            .expect("take filler")
            .expect("filler available");
        assert_eq!((offset, sent), (0, filler));
        provider.flush_handshake_io().expect("transfer held rustls output");
        assert_eq!(provider.pending_crypto_level, None);
        assert_eq!(provider.crypto_initial.next_crypto_frame(1200), Ok(None));
        provider
            .crypto_initial
            .ack_crypto(0, limit as u64)
            .expect("ACK filler to release retention capacity");
        let mut recovered = Vec::new();
        while let Some((offset, bytes)) =
            provider.next_crypto_frame(Level::Initial, 1200).expect("send held ClientHello")
        {
            assert_eq!(offset, limit as u64 + recovered.len() as u64);
            recovered.extend_from_slice(&bytes);
        }
        assert_eq!(recovered, held_client_hello);
        assert_eq!(provider.bytes_sent, recovered.len());
    }

    #[test]
    fn blocked_server_hello_keeps_handshake_key_change_with_its_output() {
        let mut client = provider_with_manual_clock();
        let (_, client_hello) = client
            .next_crypto_frame(Level::Initial, usize::MAX)
            .expect("read ClientHello")
            .expect("ClientHello available");
        let environment = crate::env_utils::EnvSnapshot::capture();
        let clock = crate::time_source::ProtocolClock::default();
        let mut server = RustlsProviderImpl::new_with_ca_with_snapshot_and_clock(
            true,
            false,
            PROTOCOL_VERSION,
            &[],
            None,
            &environment,
            &clock,
        )
        .expect("server provider");
        let limit = qf_transport_crypto_stream::MAX_CRYPTO_BUFFERED_BYTES;
        server.crypto_initial.send(&vec![0xA5; limit]).expect("fill Initial queue");
        server.provide_quic_data(Level::Initial, &client_hello).expect("consume real ClientHello");
        assert_eq!(server.pending_crypto_level, Some(Level::Initial));
        assert!(server.pending_crypto_key_change.is_some());
        let keys = parking_lot::RwLock::new(crate::transport::packet::CryptoContext::default());
        server.poll_secrets_and_install(&keys).expect("poll blocked server keys");
        assert!(keys.read().seal_handshake.is_none());

        server
            .crypto_initial
            .next_crypto_frame(limit)
            .expect("drain filler")
            .expect("filler available");
        server.flush_handshake_io().expect("transfer held ServerHello");
        assert_eq!(server.pending_crypto_level, None);
        assert!(server.pending_crypto_key_change.is_none());
        server.poll_secrets_and_install(&keys).expect("install retained Handshake keys");
        assert!(keys.read().seal_handshake.is_some());
    }
}

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

        let first_provider =
            RustlsProviderImpl::new_with_ca(false, false, PROTOCOL_VERSION, &[], Some(first_path))
                .expect("first client provider");
        let second_provider =
            RustlsProviderImpl::new_with_ca(false, false, PROTOCOL_VERSION, &[], Some(second_path))
                .expect("second client provider");
        let repeated_provider =
            RustlsProviderImpl::new_with_ca(false, false, PROTOCOL_VERSION, &[], Some(first_path))
                .expect("repeated same-path client provider");

        assert_eq!(first_provider.client_ca_path.as_deref(), Some(first_path));
        assert_eq!(second_provider.client_ca_path.as_deref(), Some(second_path));
        assert_eq!(repeated_provider.client_ca_path.as_deref(), Some(first_path));
    }
}

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
