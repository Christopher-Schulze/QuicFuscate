// --- 2. Browser/OS Fingerprinting ---

/// Defines the target browser for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum BrowserProfile {
    /// Google Chrome fingerprint (Chromium-based).
    #[serde(alias = "Chrome")]
    Chrome,
    /// Mozilla Firefox fingerprint.
    #[serde(alias = "Firefox")]
    Firefox,
    /// Apple Safari fingerprint.
    #[serde(alias = "Safari")]
    Safari,
    /// Microsoft Edge fingerprint (Chromium-based with Edge-specific tweaks).
    #[serde(alias = "Edge")]
    Edge,
}

impl std::str::FromStr for BrowserProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chrome" => Ok(BrowserProfile::Chrome),
            "firefox" => Ok(BrowserProfile::Firefox),
            "safari" => Ok(BrowserProfile::Safari),
            "edge" => Ok(BrowserProfile::Edge),
            _ => Err(()),
        }
    }
}

/// Defines the target operating system for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum OsProfile {
    /// Microsoft Windows platform fingerprint.
    #[serde(alias = "Windows")]
    Windows,
    /// Apple macOS platform fingerprint.
    #[serde(alias = "MacOS", alias = "mac", alias = "Mac")]
    MacOS,
    /// Linux desktop/server platform fingerprint.
    #[serde(alias = "Linux")]
    Linux,
    /// Apple iOS mobile platform fingerprint.
    #[serde(alias = "IOS", alias = "iOS")]
    IOS,
    /// Google Android mobile platform fingerprint.
    #[serde(alias = "Android")]
    Android,
}

impl std::str::FromStr for OsProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "windows" => Ok(OsProfile::Windows),
            "macos" | "mac" => Ok(OsProfile::MacOS),
            "linux" => Ok(OsProfile::Linux),
            "ios" => Ok(OsProfile::IOS),
            "android" => Ok(OsProfile::Android),
            _ => Err(()),
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
            _ => Self::new(BrowserProfile::Chrome, OsProfile::Windows),
        };

        // Generate sophisticated ClientHello using browser-specific fingerprinting
        profile.client_hello = Some(tls_cover::TlsCover::generate_client_hello(
            profile.browser,
            profile.os,
            None, // SNI will be added dynamically
        ));

        // Generate matching ServerHello using the same cipher resolution as TLS Cover encryption.
        // This ensures the advertised cipher in ServerHello matches the actual cover cipher,
        // preventing DPI fingerprinting via cipher mismatch (TODO-288).
        let pref = TlsCoverProvider::cipher_preference_from_env();
        let cipher_suite = TlsCoverProvider::resolve_cipher_suite(pref).tls_id();
        profile.server_hello = Some(ServerHelloParamsOwned {
            tls_version: 0x0303,
            cipher_suite,
            extensions: Vec::new(),
        });
        profile.certificate = None;
        profile
    }
}
