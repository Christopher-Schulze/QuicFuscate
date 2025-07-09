use quicfuscate::fake_tls::{
    ClientHelloParams, FakeTls, ServerHelloParams, DEFAULT_CERTIFICATE, DEFAULT_CLIENT_HELLO,
    DEFAULT_SERVER_HELLO,
};
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};

#[test]
fn fake_tls_handshake_sequence() {
    let mut fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    fp.client_hello = None; // ensure default is used
    let hello = FakeTls::client_hello(&fp);
    assert_eq!(hello, DEFAULT_CLIENT_HELLO);

    let resp = FakeTls::server_response();
    assert_eq!(resp, [DEFAULT_SERVER_HELLO, DEFAULT_CERTIFICATE].concat());

    let all = FakeTls::handshake(&fp);
    let mut expected = DEFAULT_CLIENT_HELLO.to_vec();
    expected.extend_from_slice(&resp);
    assert_eq!(all, expected);
}

#[test]
fn custom_handshake_builder() {
    let ch = ClientHelloParams {
        tls_version: 0x0303,
        cipher_suites: &[0x1301, 0x1302],
        extensions: &[],
    };
    let sh = ServerHelloParams {
        tls_version: 0x0303,
        cipher_suite: 0x1301,
        extensions: &[],
    };

    let hello = FakeTls::client_hello_custom(ch);
    let server = FakeTls::server_hello_custom(sh);
    assert_eq!(FakeTls::handshake_custom(ch, sh), [hello, server].concat());
}

#[test]
fn custom_certificate_support() {
    let ch = ClientHelloParams {
        tls_version: 0x0303,
        cipher_suites: &[0x1301],
        extensions: &[],
    };
    let sh = ServerHelloParams {
        tls_version: 0x0303,
        cipher_suite: 0x1301,
        extensions: &[],
    };
    let cert = b"test";
    let resp = FakeTls::server_response_custom(sh, cert);
    let mut expected = FakeTls::server_hello_custom(sh);
    expected.extend_from_slice(&FakeTls::certificate_record(cert));
    assert_eq!(resp, expected);

    let full = FakeTls::handshake_custom_with_cert(ch, sh, cert);
    let mut exp = FakeTls::client_hello_custom(ch);
    exp.extend_from_slice(&expected);
    assert_eq!(full, exp);
}
