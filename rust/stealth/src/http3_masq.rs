use crate::browser::{BrowserProfile, default_headers};
use std::collections::HashMap;

pub struct Masquerade {
    profile: BrowserProfile,
    enabled: bool,
}

impl Masquerade {
    pub fn new(profile: BrowserProfile) -> Self { Self { profile, enabled: false } }

    pub fn enable(&mut self, enable: bool) { self.enabled = enable; }

    pub fn set_profile(&mut self, profile: BrowserProfile) {
        self.profile = profile;
    }

    pub fn headers(&self) -> HashMap<String, String> {
        if self.enabled {
            default_headers(self.profile)
        } else {
            HashMap::new()
        }
    }

    /// Generate a basic set of HTTP/3 request headers for the given path.
    pub fn request_headers(&self, path: &str) -> HashMap<String, String> {
        if !self.enabled {
            return HashMap::new();
        }

        let mut h = default_headers(self.profile);
        h.insert(":method".into(), "GET".into());
        h.insert(":scheme".into(), "https".into());
        h.insert(":path".into(), path.into());
        h.insert(":authority".into(), "example.com".into());
        h
    }

    /// Encode request headers using the provided QPACK engine.
    pub fn encode_request(&self, path: &str, qpack: &mut crate::qpack::QpackEngine) -> Vec<u8> {
        let headers = self.request_headers(path);
        let pairs: Vec<(String, String)> = headers.into_iter().collect();
        qpack.encode(&pairs)
    }
}
