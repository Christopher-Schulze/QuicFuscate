// --- 10. TLS Client Hello Spoofing

/// Allows manipulation of the TLS ClientHello to mimic real browser behaviour.
///
/// ClientHello bytes are synthesized in-memory using integrated fingerprinting,
/// replacing legacy on-disk dumps.
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
    /// Generate ClientHello with advanced features.
    pub fn generate_advanced_hello(
        browser: BrowserProfile,
        os: OsProfile,
        sni: Option<&str>,
        session_tickets: Option<Vec<(Vec<u8>, u32)>>,
        enable_ech: bool,
    ) -> Vec<u8> {
        let seed = (browser as u16) ^ ((os as u16) << 8);
        let enable_grease = !matches!(browser, BrowserProfile::Safari);

        // Build extensions with all advanced features
        let mut exts = Vec::with_capacity(1024);

        // Add extensions in browser-specific order
        let ext_order = Self::get_extension_order(browser);

        for ext_name in ext_order {
            match *ext_name {
                "grease" if enable_grease => {
                    exts.extend_from_slice(&tls_cover::grease_ext(seed));
                }
                "sni" => {
                    if let Some(host) = sni {
                        exts.extend_from_slice(&tls_cover::sni_ext(host));
                    }
                }
                "session_ticket" => {
                    if let Some(ref tickets) = session_tickets {
                        exts.extend_from_slice(&Self::build_psk_extension(tickets));
                    }
                }
                "ech" if enable_ech => {
                    exts.extend_from_slice(&Self::build_ech_grease());
                }
                "supported_versions" => {
                    exts.extend_from_slice(&Self::build_supported_versions());
                }
                "key_share" => {
                    exts.extend_from_slice(&tls_cover::key_share_ext(0x001d, seed as u64));
                }
                _ => {}
            }
        }

        // Generate full ClientHello
        tls_cover::TlsCover::client_hello_custom(tls_cover::ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &Self::get_cipher_suites(browser, enable_grease, seed),
            extensions: &exts,
        })
    }

    fn get_extension_order(browser: BrowserProfile) -> &'static [&'static str] {
        match browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &[
                "grease",
                "sni",
                "ech",
                "supported_versions",
                "key_share",
                "session_ticket",
                "psk_modes",
                "signature_algorithms",
            ],
            BrowserProfile::Firefox => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "key_share",
                "session_ticket",
                "psk_modes",
                "ech",
            ],
            BrowserProfile::Safari => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "key_share",
                "session_ticket",
            ],
        }
    }

    fn get_cipher_suites(browser: BrowserProfile, grease: bool, seed: u16) -> Vec<u16> {
        let mut ciphers = match browser {
            BrowserProfile::Firefox => vec![0x1301, 0x1302, 0x1303, 0xCCA9, 0xCCA8],
            _ => vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F],
        };

        if grease {
            ciphers.insert(0, tls_cover::grease_value(seed as usize));
        }

        ciphers
    }

    fn build_psk_extension(tickets: &[(Vec<u8>, u32)]) -> Vec<u8> {
        let mut ext = Vec::with_capacity(256);

        // Extension type (pre_shared_key = 41)
        ext.extend_from_slice(&41u16.to_be_bytes());

        // Build identities
        let mut identities = Vec::new();
        for (ticket, age_ms) in tickets.iter().take(2) {
            identities.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            identities.extend_from_slice(ticket);
            identities.extend_from_slice(&age_ms.to_be_bytes());
        }

        // Extension length
        ext.extend_from_slice(&((identities.len() + 2) as u16).to_be_bytes());

        // Identities length
        ext.extend_from_slice(&(identities.len() as u16).to_be_bytes());
        ext.extend_from_slice(&identities);

        ext
    }

    fn build_ech_grease() -> Vec<u8> {
        // Build ECH GREASE extension (type 0xfe0d)
        let mut ext = Vec::with_capacity(128);
        ext.extend_from_slice(&0xfe0du16.to_be_bytes());

        // Random GREASE data (64 bytes)
        let grease_len = 64u16;
        ext.extend_from_slice(&grease_len.to_be_bytes());

        for _ in 0..grease_len {
            ext.push(rand::random());
        }

        ext
    }

    fn build_supported_versions() -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&43u16.to_be_bytes()); // Extension type
        ext.extend_from_slice(&3u16.to_be_bytes()); // Length
        ext.push(2); // Versions length
        ext.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
        ext
    }

    /// Loads a base64-encoded ClientHello dump for the given browser/OS from disk.
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

    /// Injects the given ClientHello bytes into the transport configuration (native).
    #[inline]
    fn inject_bytes(cfg: &mut crate::transport::Config, hello: &[u8]) {
        if hello.is_empty() {
            return;
        }
        // Native path: store ClientHello template and adjust GREASE/determinism knobs.
        let _ = cfg.apply_deterministic_tls_hello_template(hello);
    }

    /// Loads the specified profile and injects it into the transport config.
    ///
    /// Generates ClientHello using integrated fingerprinting for the specified browser/OS.
    /// If generation fails, this logs an error and leaves `cfg` unchanged.
    ///
    /// Side effects
    /// ------------
    /// Disables GREASE and enables deterministic hellos for the lifetime of the
    /// process TLS context. No error is returned.
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

    /// Returns a list of all available browser/OS combinations for which a
    /// ClientHello dump exists.
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
