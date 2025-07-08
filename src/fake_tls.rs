// Minimal FakeTLS record layer for fingerprinting
// Generates a forged ClientHello and synthetic server response without
// establishing a real TLS session.

use crate::stealth::FingerprintProfile;

/// Hard coded ClientHello payload used when a profile does not provide one.
/// This is not a valid TLS handshake, it merely resembles one for DPI evasion.
pub const DEFAULT_CLIENT_HELLO: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0x0f, // record header
    0x01, 0x00, 0x00, 0x0b, // handshake header
    b'f', b'a', b'k', b'e', b'-', b'c', b'l', b'i', b'e', b'n', b't',
];

/// Hard coded ServerHello payload returned by the fake server.
pub const DEFAULT_SERVER_HELLO: &[u8] = &[
    0x16, 0x03, 0x03, 0x00, 0x0f, 0x02, 0x00, 0x00, 0x0b, b'f', b'a', b'k', b'e', b'-', b's', b'e',
    b'r', b'v', b'e', b'r',
];

/// Hard coded certificate payload used by the fake server.
pub const DEFAULT_CERTIFICATE: &[u8] = &[
    0x16, 0x03, 0x03, 0x00, 0x08, 0x0b, 0x00, 0x00, 0x04, b'c', b'e', b'r', b't',
];

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

    /// Helper to build a TLS handshake record for the given handshake type and
    /// payload.
    fn record(htype: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 9);
        out.extend_from_slice(&[0x16, 0x03, 0x03]); // Handshake record, TLS 1.2
        let len = payload.len() + 4;
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.push(htype);
        let l = (payload.len() as u32).to_be_bytes();
        out.extend_from_slice(&l[1..]);
        out.extend_from_slice(payload);
        out
    }

    /// Returns the fake server response consisting of ServerHello and
    /// Certificate records.
    pub fn server_response() -> Vec<u8> {
        let mut out = Self::record(0x02, b"fake-server");
        out.extend_from_slice(&Self::record(0x0b, b"cert"));
        out
    }

    /// Generates the complete FakeTLS handshake sequence.
    pub fn handshake(profile: &FingerprintProfile) -> Vec<u8> {
        let mut out = Self::client_hello(profile);
        out.extend_from_slice(&Self::server_response());
        out
    }
}
