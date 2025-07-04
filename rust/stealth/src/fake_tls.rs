use crate::browser::{BrowserFingerprint, BrowserProfile};

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

    /// Generate a minimal fake TLS ClientHello packet.
    pub fn generate_client_hello(&self) -> Vec<u8> {
        if !self.enabled {
            return Vec::new();
        }
        // Build a fake handshake including cipher suite, extension and ALPN
        // information based on the configured browser fingerprint.
        let tls = &self.fingerprint.tls;

        let mut hello = vec![0x16, 0x03, 0x01];

        // Cipher suites
        hello.push(tls.cipher_suites.len() as u8);
        for cs in &tls.cipher_suites {
            hello.extend_from_slice(&cs.to_be_bytes());
        }

        // Extensions
        hello.push(tls.extensions.len() as u8);
        for ext in &tls.extensions {
            hello.extend_from_slice(&ext.to_be_bytes());
        }

        // ALPN identifiers
        hello.push(tls.alpn.len() as u8);
        for alpn in &tls.alpn {
            hello.push(alpn.len() as u8);
            hello.extend_from_slice(alpn.as_bytes());
        }

        hello
    }
}
