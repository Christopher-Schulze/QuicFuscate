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
}
