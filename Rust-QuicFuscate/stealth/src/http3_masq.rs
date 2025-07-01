use crate::browser::{BrowserProfile, default_headers};
use std::collections::HashMap;

pub struct Masquerade {
    profile: BrowserProfile,
}

impl Masquerade {
    pub fn new(profile: BrowserProfile) -> Self { Self { profile } }

    pub fn headers(&self) -> HashMap<String, String> {
        default_headers(self.profile)
    }
}
