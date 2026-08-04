// --- 10. TLS Client Hello Profile Catalog

/// Provides the supported browser/OS combinations for deterministic
/// compatibility and audit metadata.
///
/// The active wire ClientHello is created by rustls from [`TlsProfile`]. This
/// catalog does not expose a transport setter or a wire override path.
pub struct TlsClientHelloProfileCatalog;

impl TlsClientHelloProfileCatalog {

    /// Returns browser/OS combinations for which deterministic compatibility
    /// metadata can be generated.
    #[inline]
    pub fn available_profiles() -> Vec<(BrowserProfile, OsProfile)> {
        // Enumerate curated combos that blend in widely
        use BrowserProfile as B;
        use OsProfile as O;
        vec![
            // Windows
            (B::Chrome, O::Windows),
            (B::Firefox, O::Windows),
            (B::Edge, O::Windows),
            // macOS
            (B::Safari, O::MacOS),
            (B::Chrome, O::MacOS),
            (B::Firefox, O::MacOS),
            (B::Edge, O::MacOS),
            // Linux
            (B::Chrome, O::Linux),
            (B::Firefox, O::Linux),
            // Android
            (B::Chrome, O::Android),
            (B::Firefox, O::Android),
            (B::Edge, O::Android),
            // iOS
            (B::Safari, O::IOS),
            (B::Chrome, O::IOS),
        ]
    }
}
