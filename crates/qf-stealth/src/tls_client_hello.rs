//! Deterministic browser/OS metadata catalog for TLS ClientHello compatibility.

use crate::{BrowserProfile, OsProfile};

/// Provides the supported browser/OS combinations for deterministic
/// compatibility and audit metadata.
///
/// The active wire ClientHello is created by rustls from the TLS profile. This
/// catalog does not expose a transport setter or a wire override path.
#[doc(hidden)]
pub struct TlsClientHelloProfileCatalog;

impl TlsClientHelloProfileCatalog {
    /// Returns browser/OS combinations for which deterministic compatibility
    /// metadata can be generated.
    #[inline]
    pub fn available_profiles() -> Vec<(BrowserProfile, OsProfile)> {
        use BrowserProfile as B;
        use OsProfile as O;

        vec![
            (B::Chrome, O::Windows),
            (B::Firefox, O::Windows),
            (B::Edge, O::Windows),
            (B::Safari, O::MacOS),
            (B::Chrome, O::MacOS),
            (B::Firefox, O::MacOS),
            (B::Edge, O::MacOS),
            (B::Chrome, O::Linux),
            (B::Firefox, O::Linux),
            (B::Chrome, O::Android),
            (B::Firefox, O::Android),
            (B::Edge, O::Android),
            (B::Safari, O::IOS),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::TlsClientHelloProfileCatalog;
    use crate::{BrowserProfile, OsProfile};

    #[test]
    fn catalog_contains_the_curated_browser_os_matrix() {
        let profiles = TlsClientHelloProfileCatalog::available_profiles();
        assert_eq!(profiles.len(), 13);
        assert!(profiles.contains(&(BrowserProfile::Chrome, OsProfile::Windows)));
        assert!(profiles.contains(&(BrowserProfile::Safari, OsProfile::IOS)));
        assert!(!profiles.contains(&(BrowserProfile::Safari, OsProfile::Linux)));
    }
}
