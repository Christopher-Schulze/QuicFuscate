use crate::browser::{BrowserFingerprint, BrowserProfile};
use rustls::{self, client::ServerName, ClientConfig, ClientConnection, RootCertStore};
use std::sync::Arc;

pub struct FakeTls {
    profile: BrowserProfile,
    fingerprint: BrowserFingerprint,
    enabled: bool,
}

impl FakeTls {
    pub fn new(profile: BrowserProfile) -> Self {
        Self {
            profile,
            fingerprint: BrowserFingerprint::for_profile(profile),
            enabled: true,
        }
    }

    pub fn set_profile(&mut self, profile: BrowserProfile) {
        self.profile = profile;
        self.fingerprint = BrowserFingerprint::for_profile(profile);
    }

    pub fn enable(&mut self, e: bool) { self.enabled = e; }

    /// Generate a TLS ClientHello packet mimicking the configured browser.
    pub fn generate_client_hello(&self) -> Vec<u8> {
        if !self.enabled {
            return Vec::new();
        }

        // Map cipher suite codes to rustls SupportedCipherSuite references.
        fn map_suite(code: u16) -> Option<rustls::SupportedCipherSuite> {
            use rustls::cipher_suite::*;
            match code {
                0x1301 => Some(TLS13_AES_128_GCM_SHA256),
                0x1302 => Some(TLS13_AES_256_GCM_SHA384),
                0x1303 => Some(TLS13_CHACHA20_POLY1305_SHA256),
                _ => None,
            }
        }

        let tls = &self.fingerprint.tls;
        let suites: Vec<rustls::SupportedCipherSuite> =
            tls.cipher_suites.iter().filter_map(|&cs| map_suite(cs)).collect();

        let config = ClientConfig::builder()
            .with_cipher_suites(&suites)
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut config = config;
        config.alpn_protocols = tls
            .alpn
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect();

        let server = ServerName::try_from("example.com").unwrap();
        let mut conn = ClientConnection::new(Arc::new(config), server).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }
}
