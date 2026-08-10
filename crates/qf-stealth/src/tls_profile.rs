//! Browser-shaped TLS profile contracts shared by the stealth and TLS layers.

/// TLS profile for browser-shaped handshake configuration.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Human-readable browser user-agent string (for example, `Chrome/136.0.0.0`).
    pub name: String,
    /// TLS cipher suite IDs in preference order.
    pub cipher_suites: Vec<u16>,
    /// Supported named groups (key exchange curves) in preference order.
    pub groups: Vec<u16>,
    /// Supported signature algorithms in preference order.
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocol identifiers (for example, `h3`, `h2`, and `http/1.1`).
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
    /// Chrome 136 profile, the most common browser persona.
    pub fn chrome_130() -> Self {
        Self {
            name: "Chrome/136.0.0.0".into(),
            cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030],
            groups: vec![0x001d, 0x0017, 0x0018, 0x001e],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
            ],
            alpn_protocols: vec!["h3".into(), "h2".into(), "http/1.1".into()],
            sni: None,
            enable_0rtt: true,
            enable_ech: true,
            grease_values: vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a],
            extension_order: vec![
                0x0000, 0x0017, 0xff01, 0x000d, 0xfe0d, 0x0023, 0x0010, 0x002d, 0x0033, 0x002b,
                0x001b, 0x0039, 0x0a0a, 0x0029,
            ],
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 50)),
            cover_performance_mode: false,
        }
    }

    /// Firefox 138 profile.
    pub fn firefox_133() -> Self {
        Self {
            name: "Firefox/138.0".into(),
            cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f],
            groups: vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0401,
            ],
            alpn_protocols: vec!["h3".into(), "h2".into(), "http/1.1".into()],
            sni: None,
            enable_0rtt: true,
            enable_ech: false,
            grease_values: vec![],
            extension_order: vec![
                0x0000, 0x0023, 0x000d, 0x000a, 0x0010, 0x002d, 0x0033, 0x002b, 0x001c, 0x0039,
            ],
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 30)),
            cover_performance_mode: false,
        }
    }

    /// Safari 18.3 profile.
    pub fn safari_18() -> Self {
        Self {
            name: "Safari/18.3".into(),
            cipher_suites: vec![0x1301, 0x1302, 0xc02c, 0xc030],
            groups: vec![0x001d, 0x0017, 0x0018],
            signature_algorithms: vec![0x0403, 0x0503, 0x0807, 0x0804, 0x0805, 0x0401],
            alpn_protocols: vec!["h3".into(), "h2".into()],
            sni: None,
            enable_0rtt: true,
            enable_ech: false,
            grease_values: vec![],
            extension_order: vec![0x0000, 0x000d, 0x0010, 0x0033, 0x002b, 0x0023, 0x002d, 0x0039],
            timing_jitter: Some(std::time::Duration::from_millis(rand::random::<u64>() % 20)),
            cover_performance_mode: false,
        }
    }

    /// Edge 130 profile, derived from the Chromium persona.
    pub fn edge_130() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Edge/130.0.0.0".into();
        profile
    }

    /// Opera 115 profile, derived from Chromium with an Opera extension marker.
    pub fn opera_115() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Opera/115.0.0.0".into();
        profile.extension_order.insert(5, 0x5500);
        profile
    }

    /// Brave 1.73 profile, derived from Chromium with reduced GREASE and ECH disabled.
    pub fn brave_1_73() -> Self {
        let mut profile = Self::chrome_130();
        profile.name = "Brave/1.73.0".into();
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

#[cfg(test)]
mod tests {
    use super::TlsProfile;

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
    fn chrome_client_hello_order_is_unique_and_psk_last() {
        let profile = TlsProfile::chrome_130();
        let mut unique = profile.extension_order.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), profile.extension_order.len());
        assert_eq!(profile.extension_order.last(), Some(&0x0029));
    }

    #[test]
    fn derived_profiles_preserve_browser_specific_overrides() {
        let edge = TlsProfile::edge_130();
        let opera = TlsProfile::opera_115();
        let brave = TlsProfile::brave_1_73();
        assert_eq!(edge.name, "Edge/130.0.0.0");
        assert_eq!(opera.name, "Opera/115.0.0.0");
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
                "Chrome/136.0.0.0"
                    | "Firefox/138.0"
                    | "Safari/18.3"
                    | "Edge/130.0.0.0"
                    | "Opera/115.0.0.0"
                    | "Brave/1.73.0"
            ));
        }
    }
}
