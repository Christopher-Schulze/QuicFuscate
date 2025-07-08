// Minimal FakeTLS record layer for fingerprinting
// Generates a forged ClientHello and synthetic server response without
// establishing a real TLS session.

use crate::stealth::FingerprintProfile;

/// Hard coded ClientHello payload used when a profile does not provide one.
/// This is not a valid TLS handshake, it merely resembles one for DPI evasion.
pub const DEFAULT_CLIENT_HELLO: &[u8] = b"\x16\x03\x01\x00\x10fake-client";

/// Hard coded ServerHello payload returned by the fake server.
pub const DEFAULT_SERVER_HELLO: &[u8] = b"\x16\x03\x03\x00\x0ffake-server";

/// Hard coded certificate payload used by the fake server.
pub const DEFAULT_CERTIFICATE: &[u8] = b"\x16\x03\x03\x00\x04cert";

pub struct FakeTls;

impl FakeTls {
    /// Returns the ClientHello message for the given fingerprint profile.
    pub fn client_hello(profile: &FingerprintProfile) -> Vec<u8> {
        if let Some(ref ch) = profile.client_hello {
            ch.clone()
        } else {
            DEFAULT_CLIENT_HELLO.to_vec()
        }
    }

    /// Returns the fake server response consisting of ServerHello and
    /// Certificate records.
    pub fn server_response() -> Vec<u8> {
        [DEFAULT_SERVER_HELLO, DEFAULT_CERTIFICATE].concat()
    }

    /// Generates the complete FakeTLS handshake sequence.
    pub fn handshake(profile: &FingerprintProfile) -> Vec<u8> {
        let mut out = Self::client_hello(profile);
        out.extend_from_slice(&Self::server_response());
        out
    }
}

