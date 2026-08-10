//! Complete browser/OS fingerprint profiles and TLS Cover cipher policy.

use crate::tls_cover::{ServerHelloParamsOwned, TlsCover, TlsCoverCipherSuite};
use crate::{parse_profile_slot, BrowserProfile, OsProfile};
use qf_common::env_utils::EnvSnapshot;
use qf_cpu::{CpuFeature, FeatureDetector};

// Updated 2026-03: Chrome 136, Firefox 138, Edge 136, Safari 18.3.
const UA_CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const UA_FIREFOX_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0";
const UA_EDGE_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
const UA_EDGE_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
const UA_EDGE_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
const UA_SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15";
const UA_CHROME_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const UA_FIREFOX_MAC: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.3; rv:138.0) Gecko/20100101 Firefox/138.0";
const UA_CHROME_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const UA_FIREFOX_LINUX: &str =
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0";
const UA_CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36";
const UA_FIREFOX_ANDROID: &str =
    "Mozilla/5.0 (Android 15; Mobile; rv:138.0) Gecko/138.0 Firefox/138.0";
const UA_SAFARI_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1";
const LANG_EN_US_09: &str = "en-US,en;q=0.9";
const LANG_EN_US_05: &str = "en-US,en;q=0.5";

/// Configured TLS Cover cipher preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TlsCoverCipherPreference {
    Auto,
    ChaCha20Poly1305,
    Aes128Gcm,
}

impl TlsCoverCipherPreference {
    /// Parse the accepted environment spellings.
    #[doc(hidden)]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Some(Self::Auto),
            "chacha" | "chacha20" | "chacha20poly1305" => Some(Self::ChaCha20Poly1305),
            "aes" | "aesgcm" | "aes-gcm" | "aes128gcm" | "aes-128-gcm" | "ctr" | "aesctr" => {
                Some(Self::Aes128Gcm)
            }
            _ => None,
        }
    }

    /// Resolve the preference from one immutable environment snapshot.
    #[doc(hidden)]
    pub fn from_snapshot(environment: &EnvSnapshot) -> Self {
        environment.first_with(["QUICFUSCATE_TLS_COVER_CIPHER"], Self::parse).unwrap_or(Self::Auto)
    }

    /// Report whether the runtime exposes accelerated AES.
    #[doc(hidden)]
    pub fn has_hardware_aes() -> bool {
        let detector = FeatureDetector::instance();
        detector.has_feature(CpuFeature::AESNI)
            || detector.has_feature(CpuFeature::VAES)
            || detector.has_feature(CpuFeature::AES)
    }

    /// Select the concrete cover cipher while preserving explicit overrides.
    #[doc(hidden)]
    pub fn resolve(self) -> TlsCoverCipherSuite {
        match self {
            Self::Auto if Self::has_hardware_aes() => TlsCoverCipherSuite::Aes128Gcm,
            Self::Auto => TlsCoverCipherSuite::ChaCha20Poly1305,
            Self::ChaCha20Poly1305 => TlsCoverCipherSuite::ChaCha20Poly1305,
            Self::Aes128Gcm => {
                if !Self::has_hardware_aes() {
                    log::warn!(
                        "TLS Cover AES-128-GCM requested but hardware lacks AES acceleration; using scalar fallback"
                    );
                }
                TlsCoverCipherSuite::Aes128Gcm
            }
        }
    }
}

/// Represents a complete client fingerprint profile.
#[derive(Debug, Clone)]
pub struct FingerprintProfile {
    /// Target browser identity for this profile.
    pub browser: BrowserProfile,
    /// Target operating system identity for this profile.
    pub os: OsProfile,
    /// Full User-Agent header string matching the browser/OS combination.
    pub user_agent: String,
    /// Ordered list of TLS cipher suite IANA identifiers for the ClientHello.
    pub tls_cipher_suites: Vec<u16>,
    /// Accept-Language header value matching the browser/OS locale pattern.
    pub accept_language: String,
    /// QUIC initial_max_data transport parameter (bytes).
    pub initial_max_data: u64,
    /// QUIC initial_max_stream_data_bidi_local transport parameter (bytes).
    pub initial_max_stream_data_bidi_local: u64,
    /// QUIC initial_max_stream_data_bidi_remote transport parameter (bytes).
    pub initial_max_stream_data_bidi_remote: u64,
    /// QUIC initial_max_streams_bidi transport parameter.
    pub initial_max_streams_bidi: u64,
    /// QUIC max_idle_timeout transport parameter (milliseconds).
    pub max_idle_timeout: u64,
    /// Pre-built deterministic ClientHello bytes for compatibility and audit metadata.
    pub client_hello: Option<Vec<u8>>,
    /// Synthetic ServerHello parameters for TLS Cover parity.
    pub server_hello: Option<ServerHelloParamsOwned>,
    /// Optional synthetic certificate chain for TLS Cover.
    pub certificate: Option<Vec<u8>>,
}

impl FingerprintProfile {
    /// Creates a new profile for a given browser and OS combination, with harmonized values.
    pub fn new(browser: BrowserProfile, os: OsProfile) -> Self {
        let environment = EnvSnapshot::capture();
        Self::new_with_snapshot(browser, os, &environment)
    }

    /// Creates a profile only when the requested browser/OS pair is supported.
    ///
    /// [`FingerprintProfile::new`] retains a compatibility fallback for legacy
    /// callers. Configuration and CLI boundaries use this constructor so an
    /// unsupported pair cannot silently become Chrome/Windows.
    pub fn try_new(browser: BrowserProfile, os: OsProfile) -> Result<Self, String> {
        let profile = Self::new(browser, os);
        if profile.browser != browser || profile.os != os {
            return Err(format!("unsupported browser/OS combination {browser:?}@{os:?}"));
        }
        Ok(profile)
    }

    #[doc(hidden)]
    pub fn new_with_snapshot(
        browser: BrowserProfile,
        os: OsProfile,
        environment: &EnvSnapshot,
    ) -> Self {
        let mut profile = match (browser, os) {
            // --- Windows Profiles ---
            (BrowserProfile::Chrome, OsProfile::Windows) => Self {
                browser, os,                user_agent: UA_CHROME_WIN.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
           (BrowserProfile::Firefox, OsProfile::Windows) => Self {
                browser, os,                user_agent: UA_FIREFOX_WIN.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
           (BrowserProfile::Edge, OsProfile::Windows) => Self {
               browser, os,               user_agent: UA_EDGE_WIN.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
           (BrowserProfile::Edge, OsProfile::MacOS) => Self {
               browser, os,               user_agent: UA_EDGE_MAC.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
           (BrowserProfile::Edge, OsProfile::Linux) => Self {
               browser, os,               user_agent: UA_EDGE_LINUX.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
            // --- macOS Profiles ---
           (BrowserProfile::Safari, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_SAFARI_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 15_728_640,
                initial_max_stream_data_bidi_local: 2_097_152,
                initial_max_stream_data_bidi_remote: 2_097_152,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 45_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_CHROME_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_FIREFOX_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::Linux) => Self {
                browser, os,                user_agent: UA_CHROME_LINUX.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::Linux) => Self {
                browser, os,                user_agent: UA_FIREFOX_LINUX.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::Android) => Self {
                browser, os,                user_agent: UA_CHROME_ANDROID.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::Android) => Self {
                browser, os,                user_agent: UA_FIREFOX_ANDROID.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Edge, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36 EdgA/136.0.0.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Safari, OsProfile::IOS) => Self {
                browser, os,                user_agent: UA_SAFARI_IOS.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            // --- Fallback Profile ---
            _ => Self::new_with_snapshot(BrowserProfile::Chrome, OsProfile::Windows, environment),
        };

        // Generate sophisticated ClientHello using browser-specific fingerprinting
        profile.client_hello = Some(TlsCover::generate_client_hello_with_snapshot(
            profile.browser,
            profile.os,
            None, // SNI will be added dynamically
            environment,
        ));

        // Generate matching ServerHello using the same cipher resolution as TLS Cover encryption.
        // This ensures the advertised cipher in ServerHello matches the actual cover cipher,
        // preventing DPI fingerprinting via cipher mismatch (TODO-288).
        let cipher_suite = TlsCoverCipherPreference::from_snapshot(environment).resolve().tls_id();
        profile.server_hello = Some(ServerHelloParamsOwned {
            tls_version: 0x0303,
            cipher_suite,
            extensions: Vec::new(),
        });
        profile.certificate = None;
        profile
    }
}

/// Resolve one validated rotation slot into a concrete fingerprint.
///
/// `FingerprintProfile::new` has a historical fallback for unsupported
/// browser/OS combinations. Rotation configuration must not inherit that
/// fallback because it would silently replace the requested persona.
#[doc(hidden)]
pub fn parse_fingerprint_profile_slot(
    value: &str,
    default_os: OsProfile,
) -> Result<FingerprintProfile, String> {
    let (browser, os) = parse_profile_slot(value, default_os)?;
    FingerprintProfile::try_new(browser, os)
        .map_err(|_| format!("unsupported browser/OS combination '{value}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_profile_owns_complete_browser_contract() {
        let profile = FingerprintProfile::new_with_snapshot(
            BrowserProfile::Firefox,
            OsProfile::Linux,
            &EnvSnapshot::default(),
        );

        assert_eq!(profile.browser, BrowserProfile::Firefox);
        assert_eq!(profile.os, OsProfile::Linux);
        assert!(profile.user_agent.contains("Firefox/138.0"));
        assert_eq!(profile.accept_language, LANG_EN_US_05);
        assert!(profile.client_hello.as_ref().is_some_and(|hello| hello.len() > 50));
        assert!(profile.server_hello.is_some());
    }

    #[test]
    fn compatibility_constructor_falls_back_but_strict_constructor_rejects() {
        let fallback = FingerprintProfile::new_with_snapshot(
            BrowserProfile::Edge,
            OsProfile::IOS,
            &EnvSnapshot::default(),
        );

        assert_eq!(fallback.browser, BrowserProfile::Chrome);
        assert_eq!(fallback.os, OsProfile::Windows);
        assert!(FingerprintProfile::try_new(BrowserProfile::Edge, OsProfile::IOS).is_err());
    }

    #[test]
    fn rotation_slot_parser_preserves_strict_persona_validation() {
        let profile = parse_fingerprint_profile_slot("firefox@linux", OsProfile::Windows)
            .expect("supported Firefox/Linux persona");
        assert_eq!((profile.browser, profile.os), (BrowserProfile::Firefox, OsProfile::Linux));
        assert!(parse_fingerprint_profile_slot("edge@ios", OsProfile::Windows).is_err());
    }

    #[test]
    fn cipher_preference_parser_and_explicit_resolution_are_stable() {
        assert_eq!(
            TlsCoverCipherPreference::parse("chacha20poly1305"),
            Some(TlsCoverCipherPreference::ChaCha20Poly1305)
        );
        assert_eq!(
            TlsCoverCipherPreference::parse("aes-128-gcm"),
            Some(TlsCoverCipherPreference::Aes128Gcm)
        );
        assert_eq!(TlsCoverCipherPreference::parse("unknown"), None);
        assert_eq!(
            TlsCoverCipherPreference::ChaCha20Poly1305.resolve(),
            TlsCoverCipherSuite::ChaCha20Poly1305
        );
        assert_eq!(TlsCoverCipherPreference::Aes128Gcm.resolve(), TlsCoverCipherSuite::Aes128Gcm);
    }
}
