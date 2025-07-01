use crate::browser::BrowserProfile;

pub struct FakeTls {
    profile: BrowserProfile,
}

impl FakeTls {
    pub fn new(profile: BrowserProfile) -> Self { Self { profile } }

    /// Generate a minimal fake TLS ClientHello packet.
    pub fn generate_client_hello(&self) -> Vec<u8> {
        // This is purely illustrative and not a real TLS handshake.
        vec![0x16, 0x03, 0x01, 0x00, 0x2a]
    }
}
