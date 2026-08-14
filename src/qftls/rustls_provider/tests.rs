use super::*;

#[test]
fn default_transport_params_encode_requested_udp_payload_size() {
    let params = RustlsProviderImpl::default_transport_params(1413)
        .expect("custom UDP payload size must produce valid transport parameters");
    let mut offset = 0;
    let mut max_udp_payload_size = None;
    while offset < params.len() {
        let (parameter_id, parameter_id_len) =
            qf_transport_pn::varint::read_varint(&params[offset..]).expect("parameter id");
        offset += parameter_id_len;
        let (parameter_length, parameter_length_len) =
            qf_transport_pn::varint::read_varint(&params[offset..]).expect("parameter length");
        offset += parameter_length_len;
        let parameter_length = usize::try_from(parameter_length).expect("parameter length usize");
        let end = offset.checked_add(parameter_length).expect("parameter end");
        assert!(end <= params.len(), "parameter must stay within the encoded buffer");
        if parameter_id == 0x03 {
            let (value, value_len) =
                qf_transport_pn::varint::read_varint(&params[offset..end]).expect("payload value");
            assert_eq!(value_len, parameter_length);
            max_udp_payload_size = Some(value);
        }
        offset = end;
    }

    assert_eq!(max_udp_payload_size, Some(1413));
    assert!(RustlsProviderImpl::default_transport_params(1199).is_err());
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
