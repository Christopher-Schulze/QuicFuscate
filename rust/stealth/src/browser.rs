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

/// Simplified representation of a browser fingerprint used for
/// HTTP header generation and TLS emulation.
pub struct BrowserFingerprint {
    pub browser: BrowserType,
    pub os: OperatingSystem,
    pub user_agent: String,
}

impl BrowserFingerprint {
    pub fn new(browser: BrowserType, os: OperatingSystem, user_agent: String) -> Self {
        Self { browser, os, user_agent }
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
