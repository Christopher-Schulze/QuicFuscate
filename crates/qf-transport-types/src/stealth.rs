//! Root-independent transport stealth value contracts.

/// Browser congestion fingerprint used by the transport congestion shaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    /// Chromium/Chrome congestion signature.
    Chrome,
    /// Firefox congestion signature.
    Firefox,
    /// Safari/WebKit congestion signature.
    Safari,
    /// Microsoft Edge congestion signature (same gain table as Chrome).
    Edge,
}

#[cfg(test)]
mod tests {
    use super::BrowserProfile;

    #[test]
    fn browser_profiles_are_distinct_transport_contracts() {
        assert_ne!(BrowserProfile::Chrome, BrowserProfile::Firefox);
        assert_ne!(BrowserProfile::Safari, BrowserProfile::Edge);
    }
}
