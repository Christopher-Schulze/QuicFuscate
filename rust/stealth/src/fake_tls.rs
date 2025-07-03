use crate::browser::{BrowserProfile, TlsFingerprint};

pub struct FakeTls {
    profile: BrowserProfile,
    fingerprint: TlsFingerprint,
}

impl FakeTls {
    pub fn new(profile: BrowserProfile) -> Self {
        Self { profile, fingerprint: TlsFingerprint::default() }
    }

    pub fn set_profile(&mut self, profile: BrowserProfile) {
        self.profile = profile;
        self.fingerprint = TlsFingerprint::default();
    }

    /// Generate a minimal fake TLS ClientHello packet.
    pub fn generate_client_hello(&self) -> Vec<u8> {
        // Build a fake handshake including cipher suite and extension count.
        let mut hello = vec![0x16, 0x03, 0x01];
        hello.push(self.fingerprint.cipher_suites.len() as u8);
        for cs in &self.fingerprint.cipher_suites {
            hello.extend_from_slice(&cs.to_be_bytes());
        }
        hello
    }
}
