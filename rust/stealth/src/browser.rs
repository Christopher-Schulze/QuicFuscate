use std::collections::HashMap;

#[derive(Clone, Copy)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

#[derive(Clone, Copy)]
pub enum OperatingSystem {
    Windows,
    MacOS,
    Linux,
    Mobile,
}

#[derive(Clone, Copy)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

/// Minimal TLS handshake fingerprint used for uTLS emulation.
#[derive(Clone)]
pub struct TlsFingerprint {
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub alpn: Vec<String>,
}

impl Default for TlsFingerprint {
    fn default() -> Self {
        Self {
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            extensions: vec![0x000a, 0x000b],
            alpn: vec!["h3".into(), "http/1.1".into()],
        }
    }
}

impl TlsFingerprint {
    /// Create a fingerprint resembling a real browser profile. The values are
    /// simplified and do not represent the full set of extensions a modern
    /// browser would send, but they allow tests to validate profile specific
    /// behaviour.
    pub fn for_profile(profile: BrowserProfile) -> Self {
        match profile {
            BrowserProfile::Chrome => Self {
                cipher_suites: vec![0x1301, 0x1302, 0x1303, 0x1304],
                extensions: vec![0x000a, 0x000b, 0x002d],
                alpn: vec!["h3".into(), "h2".into(), "http/1.1".into()],
            },
            BrowserProfile::Firefox => Self {
                cipher_suites: vec![0x1301, 0x1302, 0x1303],
                extensions: vec![0x000a, 0x0010, 0x002b],
                alpn: vec!["h3".into(), "http/1.1".into()],
            },
            BrowserProfile::Safari => Self {
                cipher_suites: vec![0x1301, 0x1302],
                extensions: vec![0x000a, 0x0017],
                alpn: vec!["h3".into(), "h2".into(), "http/1.1".into()],
            },
            BrowserProfile::Edge => Self {
                cipher_suites: vec![0x1301, 0x1302, 0x1303],
                extensions: vec![0x000a, 0x000b, 0x0010],
                alpn: vec!["h3".into(), "http/1.1".into()],
            },
        }
    }
}

/// Simplified representation of a browser fingerprint used for
/// HTTP header generation and TLS emulation.
pub struct BrowserFingerprint {
    pub browser: BrowserType,
    pub os: OperatingSystem,
    pub user_agent: String,
    pub tls: TlsFingerprint,
}

impl BrowserFingerprint {
    pub fn new(browser: BrowserType, os: OperatingSystem, user_agent: String) -> Self {
        Self { browser, os, user_agent, tls: TlsFingerprint::default() }
    }

    /// Create a fingerprint from a predefined browser profile.
    pub fn for_profile(profile: BrowserProfile) -> Self {
        let (browser, ua) = match profile {
            BrowserProfile::Chrome => (BrowserType::Chrome, "Mozilla/5.0 Chrome"),
            BrowserProfile::Firefox => (BrowserType::Firefox, "Mozilla/5.0 Firefox"),
            BrowserProfile::Safari => (BrowserType::Safari, "Mozilla/5.0 Safari"),
            BrowserProfile::Edge => (BrowserType::Edge, "Mozilla/5.0 Edge"),
        };
        Self {
            browser,
            os: OperatingSystem::Windows,
            user_agent: ua.into(),
            tls: TlsFingerprint::for_profile(profile),
        }
    }

    /// Generate a small set of HTTP headers matching the fingerprint.
    pub fn generate_http_headers(&self) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("User-Agent".to_string(), self.user_agent.clone());
        h.insert("Accept".to_string(), "*/*".into());
        h
    }
}

pub fn default_headers(profile: BrowserProfile) -> HashMap<String, String> {
    match profile {
        BrowserProfile::Chrome => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Chrome".into()),
        ]),
        BrowserProfile::Firefox => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Firefox".into()),
        ]),
        BrowserProfile::Safari => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Safari".into()),
        ]),
        BrowserProfile::Edge => HashMap::from([
            ("user-agent".into(), "Mozilla/5.0 Edge".into()),
        ]),
    }
}
