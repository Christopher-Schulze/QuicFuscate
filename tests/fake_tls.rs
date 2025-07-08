use quicfuscate::fake_tls::{FakeTls, DEFAULT_CLIENT_HELLO, DEFAULT_SERVER_HELLO, DEFAULT_CERTIFICATE};
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile, HandshakeType};

#[test]
fn fake_tls_handshake_sequence() {
    let mut fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    fp.handshake_type = HandshakeType::FakeTLS;
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
