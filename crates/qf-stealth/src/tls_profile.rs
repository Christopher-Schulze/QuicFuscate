//! Browser-shaped TLS profile contracts shared by the stealth and TLS layers.

use crate::fingerprint_profile::FingerprintProfile;
use crate::profiles::BrowserProfile;
use crate::transport_params::{transport_param_fixture, EngineFamily};

/// TLS profile for browser-shaped handshake configuration.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Browser persona this profile emulates; selects the engine fixture for
    /// transport-parameter emission.
    pub browser: BrowserProfile,
    /// Human-readable browser user-agent string (for example, `Chrome/136.0.0.0`).
    pub name: String,
    /// TLS cipher suite IDs in preference order.
    pub cipher_suites: Vec<u16>,
    /// Supported named groups (key exchange curves) in preference order.
    pub groups: Vec<u16>,
    /// Supported signature algorithms in preference order.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol identifiers (QUIC personas advertise `h3` only).
    pub alpn_protocols: Vec<String>,
    /// SNI hostname override. `None` uses the connection default.
    pub sni: Option<String>,
    /// Enable 0-RTT early data in this profile.
    pub enable_0rtt: bool,
    /// Enable Encrypted Client Hello (ECH) extension.
    pub enable_ech: bool,
    /// GREASE values to inject for fingerprint realism.
    pub grease_values: Vec<u16>,
    /// ClientHello extension ordering to match browser fingerprints.
    pub extension_order: Vec<u16>,
    /// Optional cosmetic timing jitter for fingerprint realism.
    pub timing_jitter: Option<std::time::Duration>,
    /// If true, TLS Cover runs without artificial delays.
    pub cover_performance_mode: bool,
}

impl TlsProfile {
    /// Chrome 154 profile, the most common browser persona.
    /// ClientHello fields come from the checked-in Chromium capture fixture
    /// (TODO-1047); fields rustls cannot emit (GREASE positions, ALPS, ECH,
    /// ML-KEM key shares) are documented in the fixture and filtered at the
    /// provider.
    pub fn chrome_130() -> Self {
        let fixture = transport_param_fixture(EngineFamily::Chromium);
        Self {
            browser: BrowserProfile::Chrome,
            name: "Chrome/154.0.0.0".into(),
            cipher_suites: fixture.cipher_suites().to_vec(),
            groups: fixture.supported_groups().to_vec(),
            signature_algorithms: fixture.signature_algorithms().to_vec(),
            alpn_protocols: fixture.alpn().to_vec(),
            sni: None,
            enable_0rtt: false,
            enable_ech: true,
            grease_values: vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a],
            extension_order: fixture.extension_order().unwrap_or_default().to_vec(),
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 50)),
            cover_performance_mode: false,
        }
    }

    /// Firefox 147 profile (neqo source constants).
    pub fn firefox_133() -> Self {
        let fixture = transport_param_fixture(EngineFamily::Firefox);
        Self {
            browser: BrowserProfile::Firefox,
            name: "Firefox/147.0".into(),
            cipher_suites: fixture.cipher_suites().to_vec(),
            groups: fixture.supported_groups().to_vec(),
            signature_algorithms: fixture.signature_algorithms().to_vec(),
            alpn_protocols: fixture.alpn().to_vec(),
            sni: None,
            enable_0rtt: false,
            enable_ech: false,
            grease_values: vec![],
            extension_order: fixture.extension_order().unwrap_or_default().to_vec(),
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 30)),
            cover_performance_mode: false,
        }
    }

    /// Safari 26.0 profile (catalog values pending a real capture).
    pub fn safari_18() -> Self {
        let fixture = transport_param_fixture(EngineFamily::WebKit);
        Self {
            browser: BrowserProfile::Safari,
            name: "Safari/26.0".into(),
            cipher_suites: fixture.cipher_suites().to_vec(),
            groups: fixture.supported_groups().to_vec(),
            signature_algorithms: fixture.signature_algorithms().to_vec(),
            alpn_protocols: fixture.alpn().to_vec(),
            sni: None,
            enable_0rtt: false,
            enable_ech: false,
            grease_values: vec![],
            extension_order: fixture.extension_order().unwrap_or_default().to_vec(),
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 20)),
            cover_performance_mode: false,
        }
    }

    /// Edge 153 profile, derived from the Chromium persona.
    pub fn edge_130() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Edge/153.0.0.0".into();
        profile
    }

    /// Opera 136 profile, derived from Chromium with an Opera extension marker.
    pub fn opera_115() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Opera/136.0.0.0".into();
        profile.extension_order.insert(5, 0x5500);
        profile
    }

    /// Brave 1.95 profile, derived from Chromium with reduced GREASE and ECH disabled.
    pub fn brave_1_73() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Brave/1.95.0".into();
        profile.enable_ech = false;
        profile.grease_values.clear();
        profile
    }

    /// Select a browser persona using non-security randomness.
    pub fn random() -> Self {
        use rand::Rng;

        match rand::rng().random_range(0..6u8) {
            0 => Self::chrome_130(),
            1 => Self::firefox_133(),
            2 => Self::safari_18(),
            3 => Self::edge_130(),
            4 => Self::opera_115(),
            _ => Self::brave_1_73(),
        }
    }
}

/// Build the browser-shaped TLS runtime profile for one fingerprint persona.
///
/// ClientHello fields (cipher order, groups, signature algorithms, ALPN,
/// extension order) come from the checked-in capture fixture for the
/// persona's engine family; the provider intersects them with what rustls
/// can actually emit. `FingerprintProfile::tls_cipher_suites` stays as the
/// documentation-level list but no longer overrides the fixture.
#[doc(hidden)]
pub fn profile_from_fingerprint(fingerprint: &FingerprintProfile) -> TlsProfile {
    match fingerprint.browser {
        BrowserProfile::Chrome => TlsProfile::chrome_130(),
        BrowserProfile::Firefox => TlsProfile::firefox_133(),
        BrowserProfile::Safari => TlsProfile::safari_18(),
        BrowserProfile::Edge => TlsProfile::edge_130(),
    }
}

#[cfg(test)]
mod tests {
    use super::{profile_from_fingerprint, TlsProfile};
    use crate::{BrowserProfile, FingerprintProfile, OsProfile};

    #[test]
    fn all_browser_profiles_have_aes_gcm_and_alpn() {
        let profiles = [
            TlsProfile::chrome_130(),
            TlsProfile::firefox_133(),
            TlsProfile::safari_18(),
            TlsProfile::edge_130(),
            TlsProfile::opera_115(),
            TlsProfile::brave_1_73(),
        ];

        for profile in profiles {
            assert!(!profile.cipher_suites.is_empty(), "{} has no cipher suites", profile.name);
            assert!(profile.cipher_suites.iter().any(|suite| matches!(*suite, 0x1301 | 0x1302)));
            assert_eq!(profile.alpn_protocols.first().map(String::as_str), Some("h3"));
        }
    }

    #[test]
    fn chrome_client_hello_order_matches_capture() {
        let profile = TlsProfile::chrome_130();
        let mut unique = profile.extension_order.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), profile.extension_order.len());
        // Wire-captured Chrome 154 ends the extension block with ECH.
        assert_eq!(profile.extension_order.last(), Some(&0xfe0d));
    }

    #[test]
    fn derived_profiles_preserve_browser_specific_overrides() {
        let edge = TlsProfile::edge_130();
        let opera = TlsProfile::opera_115();
        let brave = TlsProfile::brave_1_73();
        assert_eq!(edge.name, "Edge/153.0.0.0");
        assert_eq!(opera.name, "Opera/136.0.0.0");
        assert!(opera.extension_order.contains(&0x5500));
        assert!(!brave.enable_ech);
        assert!(brave.grease_values.is_empty());
    }

    #[test]
    fn random_profile_stays_within_supported_personas() {
        for _ in 0..64 {
            let profile = TlsProfile::random();
            assert!(matches!(
                profile.name.as_str(),
                "Chrome/154.0.0.0"
                    | "Firefox/147.0"
                    | "Safari/26.0"
                    | "Edge/153.0.0.0"
                    | "Opera/136.0.0.0"
                    | "Brave/1.95.0"
            ));
        }
    }

    #[test]
    fn fingerprint_conversion_is_deterministic_and_prefers_h3() {
        let fingerprint = FingerprintProfile::new(BrowserProfile::Firefox, OsProfile::Linux);
        let first = profile_from_fingerprint(&fingerprint);
        let second = profile_from_fingerprint(&fingerprint);
        assert_eq!(first.name, second.name);
        assert_eq!(first.cipher_suites, second.cipher_suites);
        assert_eq!(first.groups, second.groups);
        assert_eq!(first.extension_order, second.extension_order);
        assert_eq!(first.alpn_protocols, second.alpn_protocols);
        assert_eq!(first.alpn_protocols, vec!["h3".to_string()]);
    }

    #[test]
    fn fingerprint_conversion_maps_every_browser_persona() {
        let cases = [
            (BrowserProfile::Chrome, OsProfile::Windows, "Chrome"),
            (BrowserProfile::Firefox, OsProfile::Linux, "Firefox"),
            (BrowserProfile::Safari, OsProfile::MacOS, "Safari"),
            (BrowserProfile::Edge, OsProfile::Windows, "Edge"),
        ];
        for (browser, os, expected_name) in cases {
            let profile = profile_from_fingerprint(&FingerprintProfile::new(browser, os));
            assert!(profile.name.contains(expected_name));
        }
    }

    #[test]
    fn fingerprint_conversion_uses_fixture_cipher_truth() {
        // The profile carries the captured cipher list verbatim (including
        // CHACHA20 for engines that offer it); the AES-GCM-only wire policy
        // is enforced by the rustls provider projection, not by editing the
        // persona data.
        for (browser, os) in [
            (BrowserProfile::Chrome, OsProfile::Windows),
            (BrowserProfile::Firefox, OsProfile::Linux),
            (BrowserProfile::Safari, OsProfile::MacOS),
            (BrowserProfile::Edge, OsProfile::Windows),
        ] {
            let profile = profile_from_fingerprint(&FingerprintProfile::new(browser, os));
            let fixture = crate::transport_params::transport_param_fixture(
                crate::transport_params::EngineFamily::from_browser(profile.browser),
            );
            assert_eq!(profile.cipher_suites, fixture.cipher_suites());
            assert!(profile.cipher_suites.iter().any(|s| matches!(*s, 0x1301 | 0x1302)));
        }
    }
}
