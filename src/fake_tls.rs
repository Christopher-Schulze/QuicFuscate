// Minimal FakeTLS record layer for fingerprinting
// Generates a forged ClientHello and synthetic server response without
// establishing a real TLS session.

use crate::stealth::FingerprintProfile;

/// Parameters used to craft a minimal ClientHello message.
#[derive(Clone, Copy)]
pub struct ClientHelloParams<'a> {
    /// TLS protocol version (e.g. `0x0303` for TLS 1.2).
    pub tls_version: u16,
    /// List of cipher suites encoded as IANA identifiers.
    pub cipher_suites: &'a [u16],
    /// Raw extension block to append after the compression method.
    pub extensions: &'a [u8],
}

/// Parameters used to craft a minimal ServerHello message.
#[derive(Clone, Copy)]
pub struct ServerHelloParams<'a> {
    /// TLS protocol version returned by the server.
    pub tls_version: u16,
    /// Selected cipher suite encoded as IANA identifier.
    pub cipher_suite: u16,
    /// Raw extension block of the server response.
    pub extensions: &'a [u8],
}

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

    /// Builds a minimal ClientHello record using the provided parameters.
    pub fn client_hello_custom(params: ClientHelloParams) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&params.tls_version.to_be_bytes());
        payload.extend_from_slice(&[0u8; 32]); // random
        payload.push(0); // session id len
        payload.extend_from_slice(&((params.cipher_suites.len() * 2) as u16).to_be_bytes());
        for cs in params.cipher_suites {
            payload.extend_from_slice(&cs.to_be_bytes());
        }
        payload.push(1); // compression methods len
        payload.push(0); // null compression
        payload.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
        payload.extend_from_slice(params.extensions);
        Self::record(0x01, &payload)
    }

    /// Builds a minimal ServerHello record using the provided parameters.
    pub fn server_hello_custom(params: ServerHelloParams) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&params.tls_version.to_be_bytes());
        payload.extend_from_slice(&[0u8; 32]); // random
        payload.push(0); // session id len
        payload.extend_from_slice(&params.cipher_suite.to_be_bytes());
        payload.push(0); // null compression
        payload.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
        payload.extend_from_slice(params.extensions);
        Self::record(0x02, &payload)
    }

    /// Builds a full FakeTLS handshake from explicit parameters.
    pub fn handshake_custom(ch: ClientHelloParams, sh: ServerHelloParams) -> Vec<u8> {
        let mut out = Self::client_hello_custom(ch);
        out.extend_from_slice(&Self::server_hello_custom(sh));
        out
    }

    /// Returns the fake server response consisting of ServerHello and a dummy
    /// certificate record.
    pub fn server_response() -> Vec<u8> {
        let mut out = DEFAULT_SERVER_HELLO.to_vec();
        out.extend_from_slice(DEFAULT_CERTIFICATE);
        out
    }

    /// Generates the complete FakeTLS handshake sequence.
    pub fn handshake(profile: &FingerprintProfile) -> Vec<u8> {
        if profile.client_hello.is_none() {
            let ch_params = ClientHelloParams {
                tls_version: 0x0303,
                cipher_suites: &profile.tls_cipher_suites,
                extensions: &[],
            };
            let sh_params = ServerHelloParams {
                tls_version: 0x0303,
                cipher_suite: *profile.tls_cipher_suites.first().unwrap_or(&0x1301),
                extensions: &[],
            };
            Self::handshake_custom(ch_params, sh_params)
        } else {
            let mut out = Self::client_hello(profile);
            out.extend_from_slice(&Self::server_response());
            out
        }
    }
}
