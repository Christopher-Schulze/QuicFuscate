#![cfg(feature = "rust-tests")]

use quicfuscate::qftls::{profile_from_fingerprint, TlsProfile};
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};

fn assert_tls13_only(cipher_suites: &[u16]) {
    assert!(!cipher_suites.is_empty(), "TLS 1.3 suite list must not be empty");
    for (index, suite) in cipher_suites.iter().enumerate() {
        assert!(
            matches!(*suite, 0x1301 | 0x1302 | 0x1303),
            "non-TLS-1.3 suite {suite:#x} is not in the browser fixture"
        );
        assert!(
            !cipher_suites[..index].contains(suite),
            "cipher suite {suite:#x} must not be duplicated"
        );
    }
}

#[test]
fn chrome_family_profiles_are_h3_and_tls13_only() {
    let profiles = [
        TlsProfile::chrome_130(),
        TlsProfile::edge_130(),
        TlsProfile::opera_115(),
        TlsProfile::brave_1_73(),
    ];

    for p in profiles {
        assert!(!p.alpn_protocols.is_empty(), "ALPN list must not be empty");
        assert_eq!(p.alpn_protocols[0], "h3");
        assert_tls13_only(&p.cipher_suites);
    }
}

#[test]
fn firefox_and_safari_profiles_keep_policy() {
    let firefox = TlsProfile::firefox_133();
    let safari = TlsProfile::safari_18();

    for p in [firefox, safari] {
        assert!(!p.alpn_protocols.is_empty(), "ALPN list must not be empty");
        assert_eq!(p.alpn_protocols[0], "h3");
        assert_tls13_only(&p.cipher_suites);
    }
}

#[test]
fn brave_profile_disables_ech_and_grease() {
    let p = TlsProfile::brave_1_73();
    assert!(!p.enable_ech, "Brave disables ECH per policy");
    assert!(p.grease_values.is_empty(), "Brave should not advertise GREASE");
}

#[test]
fn fingerprint_profile_preserves_captured_cipher_order() {
    let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let p = profile_from_fingerprint(&fp);
    assert_eq!(p.alpn_protocols[0], "h3");
    assert_eq!(p.cipher_suites.as_slice(), &[0x1301, 0x1302, 0x1303]);
}
