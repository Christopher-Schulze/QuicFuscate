// --- 10. TLS Client Hello Spoofing

/// Provides deterministic browser/OS persona metadata and compatibility templates.
///
/// The active wire ClientHello is created by rustls from [`TlsProfile`]. The
/// synthesized bytes retained by this helper are not a runtime wire override.
/// Profiles are referenced via [`BrowserProfile`] and [`OsProfile`].
pub struct TlsClientHelloSpoofer;

// Cache for decoded ClientHello profiles to avoid repeated IO/base64 work.
// Reduce clippy::type_complexity by factoring nested generic types into aliases
type ProfileKey = (BrowserProfile, OsProfile);
type ChloBytes = Arc<Vec<u8>>;
type ChloCacheMap = HashMap<ProfileKey, ChloBytes>;
type ChloCache = Mutex<ChloCacheMap>;

static CHLO_CACHE: std::sync::OnceLock<ChloCache> = std::sync::OnceLock::new();

impl TlsClientHelloSpoofer {
    /// Builds a deterministic ClientHello template for the given browser/OS.
    #[inline]
    fn load_client_hello(browser: BrowserProfile, os: OsProfile) -> Option<Vec<u8>> {
        // Fast path: cached profile
        let cache = CHLO_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(guard) = cache.lock() {
            if let Some(arc_bytes) = guard.get(&(browser, os)) {
                return Some((**arc_bytes).clone());
            }
        }
        // Generate ClientHello using integrated fingerprinting
        let bytes = tls_cover::TlsCover::generate_client_hello(browser, os, None);
        if let Ok(mut guard) = cache.lock() {
            guard.insert((browser, os), Arc::new(bytes.clone()));
        }
        Some(bytes)
    }

    /// Stores the given ClientHello bytes as compatibility metadata.
    #[inline]
    fn inject_bytes(cfg: &mut crate::transport::Config, hello: &[u8]) {
        if hello.is_empty() {
            return;
        }
        // The transport field is retained for compatibility and audit inspection.
        // The active rustls connection builder does not consume it.
        let _ = cfg.apply_deterministic_tls_hello_template(hello);
    }

    /// Loads the specified profile and stores its compatibility template.
    ///
    /// Generates ClientHello using integrated fingerprinting for the specified browser/OS.
    /// If generation fails, this logs an error and leaves `cfg` unchanged.
    ///
    /// Side effects
    /// ------------
    /// This does not replace rustls or alter the active wire handshake. No error
    /// is returned.
    ///
    /// Examples
    /// --------
    /// ```text
    /// // let mut cfg = crate::transport::Config::new(crate::transport::PROTOCOL_VERSION).unwrap();
    /// // TlsClientHelloSpoofer::inject_profile(&mut cfg, BrowserProfile::Chrome, OsProfile::Windows);
    /// ```
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn inject_profile(
        cfg: &mut crate::transport::Config,
        browser: BrowserProfile,
        os: OsProfile,
    ) {
        if let Some(hello) = Self::load_client_hello(browser, os) {
            Self::inject_bytes(cfg, &hello);
        } else {
            error!("Missing ClientHello profile for {:?}/{:?}", browser, os);
        }
    }

    /// Builds and injects a ClientHello with options (SNI, GREASE)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn inject_profile_with_options(
        cfg: &mut crate::transport::Config,
        browser: BrowserProfile,
        os: OsProfile,
        sni: Option<&str>,
        enable_grease: bool,
    ) {
        // Generate ClientHello with options
        let seed = (browser as u16) ^ ((os as u16) << 8);
        let mut ciphers = match browser {
            BrowserProfile::Firefox => vec![
                0x1301, 0x1302, 0x1303, 0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC013,
                0xC014,
            ],
            _ => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014,
            ],
        };
        ciphers.retain(|cipher_suite| !tls_cover::is_client_hello_cipher_removed(*cipher_suite));

        if enable_grease {
            let grease = tls_cover::grease_value(seed as usize);
            if !ciphers.contains(&grease) {
                ciphers.insert(0, grease);
            }
        }

        let mut exts = Vec::with_capacity(512);
        if enable_grease {
            exts.extend_from_slice(&tls_cover::grease_ext(seed));
        }
        if let Some(host) = sni {
            exts.extend_from_slice(&tls_cover::sni_ext(host));
        }

        let ch = tls_cover::TlsCover::client_hello_custom(tls_cover::ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &ciphers,
            extensions: &exts,
        });
        Self::inject_bytes(cfg, &ch);
    }

    /// Returns browser/OS combinations for which a deterministic compatibility
    /// template can be generated.
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
