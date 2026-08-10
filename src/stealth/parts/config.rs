// --- 7. Stealth Manager and Configuration ---

/// Ultra-sophisticated configuration for the main StealthManager.
#[derive(Clone)]
pub struct StealthConfig {
    /// Selected high-level mode for behavior decisions.
    pub mode: StealthMode,
    /// Enable domain fronting to hide the real destination.
    pub enable_domain_fronting: bool,
    /// Initial browser profile for fingerprinting.
    pub initial_browser: BrowserProfile,
    /// Initial OS profile for fingerprinting.
    pub initial_os: OsProfile,
    /// Normalize decoded server-side tunnel ingress to the frozen OS profile.
    pub enable_network_fingerprint_normalization: bool,
    /// Suppress ICMP destination-unreachable traffic except PMTUD signals.
    pub suppress_icmp_unreachable: bool,
    /// Enable traffic padding to obscure packet sizes.
    pub enable_traffic_padding: bool,
    /// Enable timing obfuscation with random delays.
    pub enable_timing_obfuscation: bool,
    /// Enable protocol mimicry (make QUIC look like other protocols).
    pub enable_protocol_mimicry: bool,
    /// Enable dynamic fingerprint rotation.
    pub enable_fingerprint_rotation: bool,
    /// Fingerprint rotation mode: Fixed (no rotation), Slots (configured slots), All (all profiles).
    pub fingerprint_rotation_mode: RotationMode,
    /// Padding strategy: 'random', 'fixed', 'adaptive'.
    pub padding_strategy: PaddingStrategy,
    /// Maximum padding size in bytes.
    pub max_padding_size: usize,
    /// Fingerprint rotation interval in seconds.
    pub fingerprint_rotation_interval: u64,
    /// Typed browser/OS slots propagated from the engine configuration.
    pub fingerprint_rotation_profiles: Vec<(BrowserProfile, OsProfile)>,
    /// Enable DNS-over-HTTPS for domain resolution.
    pub enable_doh: bool,
    /// DoH provider endpoint URL (e.g. Cloudflare DNS JSON API).
    pub doh_provider: String,
    /// Enable real-time rate choke (token/leaky bucket) to smooth observable bitrate.
    pub enable_realtime_choke: bool,
    /// Target bitrate for choke in Mbps (0 = disabled).
    pub choke_target_mbps: u32,
    /// Allowed burst window in milliseconds.
    pub choke_burst_ms: u32,
    /// Enable Dynamic mode (start as Base and escalate intelligently).
    pub dynamic_enabled: bool,
    /// Domain list for fronting rotation (empty = use built-in CDN providers).
    pub fronting_domains: Vec<String>,
    /// Enable HTTP/3 header masquerading to mimic browser requests.
    pub enable_http3_masquerading: bool,
    /// Enable TLS Cover extras (synthetic cert chain, cover PSK).
    pub use_tls_cover: bool,
    /// Enable QPACK-encoded headers in HTTP/3 masquerade frames.
    pub use_qpack_headers: bool,
    /// **NEW**: Enable HTTP/3 Server Push Cover Traffic
    pub enable_server_push_cover: bool,
    /// Server Push cover traffic intensity (0.0 = disabled, 1.0 = maximum)
    pub server_push_intensity: f32,
    /// Base path for fake resources (e.g., "/assets", "/static")
    pub server_push_base_path: String,
    /// Minimum delay between cover traffic bursts (seconds)
    pub server_push_burst_interval: u64,
    /// Enable payload compression before encryption.
    pub compress_enabled: bool,
    /// Minimum payload length in bytes before compression is attempted.
    pub compress_min_len: usize,
    /// Compression level (higher = better ratio, more CPU).
    pub compress_level: i32,
    /// MIME patterns allowed for compression (e.g. "text/*").
    pub compress_allow: Vec<String>,
    /// MIME patterns excluded from compression (e.g. "image/*").
    pub compress_deny: Vec<String>,
    /// Target packet size in bytes for PacketNormalize padding strategy (0 = disabled).
    pub normalize_target_size: usize,
    /// Emit periodic QUIC PING frames post-handshake to maintain realistic activity patterns.
    pub enable_cover_ping: bool,
    /// Interval between cover PINGs in milliseconds (0 = disabled).
    pub cover_ping_interval_ms: u64,
}

/// FEC operation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FecMode {
    /// Disabled - no FEC.
    Off,
    /// Auto - adaptive FEC based on network conditions.
    Auto,
}

impl StealthConfig {
    fn env_first<const N: usize>(
        environment: &crate::env_utils::EnvSnapshot,
        names: [&str; N],
    ) -> Option<String> {
        environment.first(names)
    }

    fn env_bool_first<const N: usize>(
        environment: &crate::env_utils::EnvSnapshot,
        names: [&str; N],
    ) -> Option<bool> {
        environment.flag_first(names)
    }

    fn env_parse_first<T, const N: usize>(
        environment: &crate::env_utils::EnvSnapshot,
        names: [&str; N],
    ) -> Option<T>
    where
        T: std::str::FromStr,
    {
        environment.parse_first(names)
    }

    fn env_f32_first<const N: usize>(
        environment: &crate::env_utils::EnvSnapshot,
        names: [&str; N],
    ) -> Option<f32> {
        environment.parse_finite_f32_first(names)
    }

    fn env_csv_first<const N: usize>(
        environment: &crate::env_utils::EnvSnapshot,
        names: [&str; N],
    ) -> Option<Vec<String>> {
        Self::env_first(environment, names).map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
    }

    fn apply_compression_env_overrides(
        policy: &mut crate::compress::CompressionPolicy,
        environment: &crate::env_utils::EnvSnapshot,
    ) {
        if let Some(enabled) = Self::env_bool_first(environment, ["QUICFUSCATE_COMPRESS"]) {
            policy.enabled = enabled;
        }
        if let Some(min_len) = Self::env_parse_first(environment, ["QUICFUSCATE_COMPRESS_MIN"]) {
            policy.min_len = min_len;
        }
        if let Some(level) = Self::env_parse_first(environment, ["QUICFUSCATE_COMPRESS_LEVEL"]) {
            policy.level = level;
        }
        if let Some(allow) = Self::env_csv_first(environment, ["QUICFUSCATE_COMPRESS_ALLOW"]) {
            policy.allow = allow;
        }
        if let Some(deny) = Self::env_csv_first(environment, ["QUICFUSCATE_COMPRESS_DENY"]) {
            policy.deny = deny;
        }
    }

    fn transport_ack_threshold_override(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<u64> {
        Self::env_parse_first(environment, ["QUICFUSCATE_ACK_THRESHOLD"])
            .filter(|n: &u64| *n > 0)
    }

    fn transport_ack_max_delay_override(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<u64> {
        Self::env_parse_first(environment, ["QUICFUSCATE_ACK_MAX_DELAY_MS"])
    }

    fn transport_external_pacing_override(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<bool> {
        Self::env_bool_first(environment, ["QUICFUSCATE_EXTERNAL_PACING"])
    }

    fn transport_padding_max_override(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<usize> {
        Self::env_parse_first(environment, [
            "QUICFUSCATE_STEALTH_PADDING_MAX",
            "QUICFUSCATE_STEALTH_MAX_PADDING",
        ])
    }

    fn transport_padding_strategy_override(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<PaddingStrategy> {
        environment.first_with([
            "QUICFUSCATE_STEALTH_PADDING_STRATEGY",
            "QUICFUSCATE_PADDING_STRATEGY",
        ], |value| match value.to_ascii_lowercase().as_str() {
            "1" | "random" => Some(PaddingStrategy::Random),
            "2" | "fixed" => Some(PaddingStrategy::Fixed),
            "3" | "adaptive" => Some(PaddingStrategy::Adaptive),
            "4" | "browser" | "browser-mimic" | "browsermimic" => {
                Some(PaddingStrategy::BrowserMimic)
            }
            "5" | "normalize" | "packet-normalize" | "packetnormalize" => {
                Some(PaddingStrategy::PacketNormalize)
            }
            _ => None,
        })
    }

    fn transport_jitter_override_us(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<u32> {
        Self::env_parse_first(environment, ["QUICFUSCATE_STEALTH_JITTER_US"])
    }

    fn transport_adaptive_granularity_override(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<u16> {
        Self::env_parse_first(environment, ["QUICFUSCATE_STEALTH_ADAPTIVE_GRAN"])
    }

    fn transport_mimic_bias_override(
        &self,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Option<u8> {
        environment.first_with(["QUICFUSCATE_STEALTH_MIMIC_BIAS"], |value| {
            match value.to_ascii_lowercase().as_str() {
            "1" | "very_small" | "safari" => Some(1),
            "2" | "small" | "firefox" => Some(2),
            "4" | "mobile" | "android" => Some(4),
            "3" | "default" | "chromium" | "chrome" | "edge" => Some(3),
            _ => None,
            }
        })
    }

    /// Creates Stealth mode - balanced features with minimal overhead (sweetspot).
    pub fn stealth() -> Self {
        Self {
            mode: StealthMode::Stealth,
            enable_domain_fronting: false,
            // Fields removed during consolidation
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_network_fingerprint_normalization: true,
            suppress_icmp_unreachable: false,
            // Enable adaptive padding with a very small budget (sweetspot)
            // to retain near-zero overhead while smoothing packet sizes.
            enable_traffic_padding: true,
            // Minimal timing obfuscation for Stealth (very low impact)
            enable_timing_obfuscation: true,
            enable_protocol_mimicry: true,
            enable_fingerprint_rotation: false, // Simple Chrome profile
            fingerprint_rotation_mode: RotationMode::Fixed,
            padding_strategy: PaddingStrategy::Adaptive,
            max_padding_size: 86, // Slightly higher for better smoothing
            fingerprint_rotation_interval: 0,
            fingerprint_rotation_profiles: Vec::new(),
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            // Real-time choke: light smoothing in Stealth (disabled by default to avoid perf hits)
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            // Dynamic disabled
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            // Server Push Cover Traffic: light in Stealth mode.
            // Real H/3 CDNs send PUSH_PROMISE on assets; omitting it breaks the browser fingerprint.
            enable_server_push_cover: true,
            server_push_intensity: 0.25,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 60,
            compress_enabled: true,
            compress_min_len: 256,
            compress_level: 5,
            compress_allow: vec!["text/*".into(), "application/json".into()],
            compress_deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
            normalize_target_size: 0,
            // Cover PING: enabled in Stealth mode - keepalive every 30 s looks like an idle browser
            enable_cover_ping: true,
            cover_ping_interval_ms: 30_000,
        }
    }

    /// Creates Anti-DPI mode - all features with aggressive settings.
    pub fn anti_dpi() -> Self {
        let domains = DomainFrontingManager::ultra_stealth();
        Self {
            mode: StealthMode::AntiDpi,
            enable_domain_fronting: true,
            fronting_domains: domains.domains().to_vec(),
            enable_http3_masquerading: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_network_fingerprint_normalization: true,
            suppress_icmp_unreachable: false,
            enable_traffic_padding: true,
            enable_timing_obfuscation: true, // Performance impact accepted
            enable_protocol_mimicry: true,
            enable_fingerprint_rotation: true,
            fingerprint_rotation_mode: RotationMode::All,
            padding_strategy: PaddingStrategy::BrowserMimic,
            max_padding_size: 256,
            fingerprint_rotation_interval: 120, // 2 minutes - aggressive enough to break persistent DPI correlations
            fingerprint_rotation_profiles: Vec::new(),
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            // Server Push Cover Traffic: ON in Anti-DPI mode (maximum stealth)
            enable_server_push_cover: true,
            server_push_intensity: 0.8, // High intensity
            server_push_base_path: "/cdn".to_string(),
            server_push_burst_interval: 15, // Frequent bursts
            // Aggressive compression defaults for Anti-DPI traffic (textual payloads)
            compress_enabled: true,
            compress_min_len: 128,
            compress_level: 7,
            compress_allow: vec!["text/*".into(), "application/json".into()],
            compress_deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
            // PacketNormalize: normalize to 1200 bytes in Anti-DPI (maximum size uniformity)
            normalize_target_size: 1200,
            // Cover PING: aggressive interval in Anti-DPI (every 15 s)
            enable_cover_ping: true,
            cover_ping_interval_ms: 15_000,
        }
    }

    /// Creates configuration from mode.
    pub fn from_mode(mode: StealthMode) -> Self {
        match mode {
            StealthMode::Off => Self::off(),
            StealthMode::Performance => Self::performance(),
            StealthMode::Stealth => Self::stealth(),
            StealthMode::AntiDpi => Self::anti_dpi(),
            StealthMode::Manual => Self::manual(),
            StealthMode::Intelligent => Self::intelligent(),
        }
    }

    /// Return the effective typed rotation pool for one connection runtime.
    ///
    /// Fixed mode has no rotation pool. Slots use the validated engine
    /// projection, while All uses the curated catalog shared by TLS metadata
    /// and runtime selection.
    pub fn rotation_profile_slots(&self) -> Vec<(BrowserProfile, OsProfile)> {
        if !self.enable_fingerprint_rotation {
            return Vec::new();
        }
        match self.fingerprint_rotation_mode {
            RotationMode::Fixed => Vec::new(),
            RotationMode::Slots => self.fingerprint_rotation_profiles.clone(),
            RotationMode::All => TlsClientHelloProfileCatalog::available_profiles(),
        }
    }

    /// Return the effective profiles as complete, deterministic fingerprints.
    pub fn rotation_profiles(&self) -> Vec<FingerprintProfile> {
        self.rotation_profile_slots()
            .into_iter()
            .map(|(browser, os)| FingerprintProfile::new(browser, os))
            .collect()
    }

    /// Creates Off mode - no stealth features.
    pub fn off() -> Self {
        Self {
            mode: StealthMode::Off,
            enable_domain_fronting: false,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_network_fingerprint_normalization: false,
            suppress_icmp_unreachable: false,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: false,
            enable_fingerprint_rotation: false,
            fingerprint_rotation_mode: RotationMode::Fixed,
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            fingerprint_rotation_profiles: Vec::new(),
            enable_doh: false,
            doh_provider: String::new(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: false,
            use_tls_cover: false,
            use_qpack_headers: false,
            // Server Push Cover Traffic: OFF in Off mode
            enable_server_push_cover: false,
            server_push_intensity: 0.0,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 0,
            compress_enabled: false,
            compress_min_len: 1024,
            compress_level: 3,
            compress_allow: Vec::new(),
            compress_deny: Vec::new(),
            normalize_target_size: 0,
            enable_cover_ping: false,
            cover_ping_interval_ms: 0,
        }
    }

    /// Creates an ultra-stealth configuration (alias for anti_dpi).
    pub fn ultra_stealth() -> Self {
        Self::anti_dpi()
    }

    /// Creates Manual mode - custom configuration.
    pub fn manual() -> Self {
        Self {
            mode: StealthMode::Manual,
            enable_domain_fronting: false,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_network_fingerprint_normalization: true,
            suppress_icmp_unreachable: false,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: false,
            enable_fingerprint_rotation: false,
            fingerprint_rotation_mode: RotationMode::Fixed,
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            fingerprint_rotation_profiles: Vec::new(),
            enable_doh: false,
            doh_provider: String::new(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: false,
            use_tls_cover: false,
            use_qpack_headers: false,
            // Server Push Cover Traffic: Manual configuration
            enable_server_push_cover: false,
            server_push_intensity: 0.3,
            server_push_base_path: "/static".to_string(),
            server_push_burst_interval: 60,
            compress_enabled: false,
            compress_min_len: 256,
            compress_level: 5,
            compress_allow: Vec::new(),
            compress_deny: Vec::new(),
            normalize_target_size: 0,
            enable_cover_ping: false,
            cover_ping_interval_ms: 0,
        }
    }

    /// Creates Performance mode - Stealth baseline but with all costly features off.
    pub fn performance() -> Self {
        Self {
            mode: StealthMode::Performance,
            // Domain fronting is not a safe baseline cover signal on modern CDNs.
            // Keep the clean path as ordinary H3/QUIC unless explicit fronting
            // domains are configured.
            enable_domain_fronting: false,
            fronting_domains: vec![],
            enable_http3_masquerading: true,
            use_tls_cover: true,
            // QPACK on: real Chrome sends QPACK; omitting it breaks the browser fingerprint
            use_qpack_headers: true,
            // Fingerprint: stable Chromium/Windows baseline
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_network_fingerprint_normalization: true,
            suppress_icmp_unreachable: false,
            // Padding: completely off
            enable_traffic_padding: false,
            // Timing obfuscation / Flow shaping: off
            enable_timing_obfuscation: false,
            // Protocol mimicry (extra transformations): off
            enable_protocol_mimicry: false,
            // Fingerprint rotation: off
            enable_fingerprint_rotation: false,
            fingerprint_rotation_mode: RotationMode::Fixed,
            // Strategy is ignored when padding disabled
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            fingerprint_rotation_profiles: Vec::new(),
            // DNS over HTTPS: ON in Performance per spec (Cloudflare)
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            // Real-time choke disabled for Performance
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            // Server Push Cover Traffic: OFF in Performance mode (performance priority)
            enable_server_push_cover: false,
            server_push_intensity: 0.0,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 0,
            compress_enabled: false,
            compress_min_len: 512,
            compress_level: 3,
            compress_allow: Vec::new(),
            compress_deny: vec!["*/*".into()],
            normalize_target_size: 0,
            enable_cover_ping: false,
            cover_ping_interval_ms: 0,
        }
    }

    /// Creates Intelligent mode - starts like Performance and escalates intelligently.
    pub fn intelligent() -> Self {
        let mut cfg = Self::performance();
        cfg.mode = StealthMode::Intelligent;
        cfg.dynamic_enabled = true;
        cfg
    }

    /// Binds the legacy protocol-mimicry flag to concrete H3/TLS cover knobs.
    ///
    /// The flag is intentionally treated as a bundle alias. This prevents a
    /// misleading state where `enable_protocol_mimicry=true` exists in config
    /// but no runtime-visible H3/TLS persona behavior is actually enabled.
    pub(crate) fn normalize_protocol_mimicry_bundle(&mut self) {
        if !self.enable_protocol_mimicry {
            return;
        }
        self.enable_http3_masquerading = true;
        self.use_qpack_headers = true;
        self.use_tls_cover = true;
    }
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self::stealth() // Default to Stealth mode
    }
}

impl StealthConfig {
    fn masque_env_flag(environment: &crate::env_utils::EnvSnapshot, name: &str) -> bool {
        Self::env_bool_first(environment, [name]).unwrap_or(false)
    }

    fn masque_proxy_override(environment: &crate::env_utils::EnvSnapshot) -> Option<String> {
        Self::env_first(environment, ["QUICFUSCATE_MASQUE_PROXY"])
    }

    /// Parses a TOML string and constructs a `StealthConfig` from the
    /// `[stealth]` table. Unknown keys are ignored. This does not apply
    /// environment overrides; call `apply_env_overrides` separately if needed.
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            stealth: Option<Section>,
            compression: Option<CompSection>,
        }

        #[derive(serde::Deserialize)]
        struct Section {
            mode: Option<StealthMode>,
            initial_browser: Option<BrowserProfile>,
            initial_os: Option<OsProfile>,
            enable_network_fingerprint_normalization: Option<bool>,
            suppress_icmp_unreachable: Option<bool>,
            #[serde(alias = "use_tls_cover_extras")]
            use_tls_cover: Option<bool>,
            enable_doh: Option<bool>,
            doh_provider: Option<String>,
            enable_http3_masquerading: Option<bool>,
            use_qpack_headers: Option<bool>,
            enable_domain_fronting: Option<bool>,
            fronting_domains: Option<Vec<String>>,
            enable_traffic_padding: Option<bool>,
            enable_timing_obfuscation: Option<bool>,
            enable_protocol_mimicry: Option<bool>,
            padding_strategy: Option<String>,
            max_padding_size: Option<usize>,
            enable_fingerprint_rotation: Option<bool>,
            fingerprint_rotation_interval: Option<u64>,
            enable_realtime_choke: Option<bool>,
            choke_target_mbps: Option<u32>,
            choke_burst_ms: Option<u32>,
            dynamic_enabled: Option<bool>,
            enable_server_push_cover: Option<bool>,
            server_push_intensity: Option<f32>,
            server_push_base_path: Option<String>,
            server_push_burst_interval: Option<u64>,
            normalize_target_size: Option<usize>,
            enable_cover_ping: Option<bool>,
            cover_ping_interval_ms: Option<u64>,
        }
        #[derive(serde::Deserialize)]
        struct CompSection {
            enabled: Option<bool>,
            min_len: Option<usize>,
            level: Option<i32>,
            allow: Option<Vec<String>>,
            deny: Option<Vec<String>>,
        }

        fn parse_padding_strategy(value: &str) -> Option<PaddingStrategy> {
            let v = value.trim().to_ascii_lowercase();
            match v.as_str() {
                "random" | "1" => Some(PaddingStrategy::Random),
                "fixed" | "constant" | "2" => Some(PaddingStrategy::Fixed),
                "adaptive" | "3" => Some(PaddingStrategy::Adaptive),
                "browser" | "browser_mimic" | "browser-mimic" | "browsermimic" | "mimic" | "4" => {
                    Some(PaddingStrategy::BrowserMimic)
                }
                "5" | "normalize" | "packet-normalize" | "packetnormalize" | "packet_normalize" => {
                    Some(PaddingStrategy::PacketNormalize)
                }
                _ => None,
            }
        }

        let root: Root = toml::from_str(s)?;
        let mut cfg = StealthConfig::default();
        if let Some(sec) = root.stealth {
            if let Some(mode) = sec.mode {
                cfg = StealthConfig::from_mode(mode);
            }
            if let Some(v) = sec.initial_browser {
                cfg.initial_browser = v;
            }
            if let Some(v) = sec.initial_os {
                cfg.initial_os = v;
            }
            if let Some(v) = sec.enable_network_fingerprint_normalization {
                cfg.enable_network_fingerprint_normalization = v;
            }
            if let Some(v) = sec.suppress_icmp_unreachable {
                cfg.suppress_icmp_unreachable = v;
            }
            if let Some(v) = sec.use_tls_cover {
                cfg.use_tls_cover = v;
            }
            if let Some(v) = sec.enable_doh {
                cfg.enable_doh = v;
            }
            if let Some(v) = sec.doh_provider {
                cfg.doh_provider = v;
            }
            if let Some(v) = sec.enable_http3_masquerading {
                cfg.enable_http3_masquerading = v;
            }
            if let Some(v) = sec.use_qpack_headers {
                cfg.use_qpack_headers = v;
            }
            if let Some(v) = sec.enable_domain_fronting {
                cfg.enable_domain_fronting = v;
            }
            if let Some(v) = sec.fronting_domains {
                cfg.fronting_domains = v;
            }
            if let Some(v) = sec.enable_traffic_padding {
                cfg.enable_traffic_padding = v;
            }
            if let Some(v) = sec.enable_timing_obfuscation {
                cfg.enable_timing_obfuscation = v;
            }
            if let Some(v) = sec.enable_protocol_mimicry {
                cfg.enable_protocol_mimicry = v;
            }
            if let Some(v) = sec.padding_strategy.as_deref().and_then(parse_padding_strategy) {
                cfg.padding_strategy = v;
            }
            if let Some(v) = sec.max_padding_size {
                cfg.max_padding_size = v;
            }
            if let Some(v) = sec.enable_fingerprint_rotation {
                cfg.enable_fingerprint_rotation = v;
            }
            if let Some(v) = sec.fingerprint_rotation_interval {
                cfg.fingerprint_rotation_interval = v;
            }
            if let Some(v) = sec.enable_realtime_choke {
                cfg.enable_realtime_choke = v;
            }
            if let Some(v) = sec.choke_target_mbps {
                cfg.choke_target_mbps = v;
            }
            if let Some(v) = sec.choke_burst_ms {
                cfg.choke_burst_ms = v;
            }
            if let Some(v) = sec.dynamic_enabled {
                cfg.dynamic_enabled = v;
            }
            if let Some(v) = sec.enable_server_push_cover {
                cfg.enable_server_push_cover = v;
            }
            if let Some(v) = sec.server_push_intensity {
                cfg.server_push_intensity = v;
            }
            if let Some(v) = sec.server_push_base_path {
                cfg.server_push_base_path = v;
            }
            if let Some(v) = sec.server_push_burst_interval {
                cfg.server_push_burst_interval = v;
            }
            if let Some(v) = sec.normalize_target_size {
                cfg.normalize_target_size = v;
            }
            if let Some(v) = sec.enable_cover_ping {
                cfg.enable_cover_ping = v;
            }
            if let Some(v) = sec.cover_ping_interval_ms {
                cfg.cover_ping_interval_ms = v;
            }
        }
        if let Some(c) = root.compression {
            if let Some(v) = c.enabled {
                cfg.compress_enabled = v;
            }
            if let Some(v) = c.min_len {
                cfg.compress_min_len = v;
            }
            if let Some(v) = c.level {
                cfg.compress_level = v;
            }
            if let Some(v) = c.allow {
                cfg.compress_allow = v;
            }
            if let Some(v) = c.deny {
                cfg.compress_deny = v;
            }
            // Push to global compression policy
            crate::compress::set_global_policy(crate::compress::CompressionPolicy {
                enabled: cfg.compress_enabled,
                min_len: cfg.compress_min_len,
                level: cfg.compress_level,
                allow: cfg.compress_allow.clone(),
                deny: cfg.compress_deny.clone(),
            });
        }
        cfg.normalize_protocol_mimicry_bundle();
        Ok(cfg)
    }

    /// Reads a TOML file at `path` and delegates to [`StealthConfig::from_toml`].
    /// Environment overrides are not applied automatically.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate the configuration values.
    pub fn validate(&self) -> Result<(), String> {
        if self.enable_doh && self.doh_provider.is_empty() {
            return Err("doh_provider must not be empty when DoH is enabled".into());
        }
        if self.use_qpack_headers && !self.enable_http3_masquerading {
            return Err("qpack headers require HTTP/3 masquerading to be enabled".into());
        }
        if self.enable_server_push_cover && !self.enable_http3_masquerading {
            return Err("server push cover requires HTTP/3 masquerading to be enabled".into());
        }
        if self.enable_realtime_choke && self.choke_target_mbps == 0 {
            return Err("realtime choke requires choke_target_mbps > 0".into());
        }
        if self.enable_fingerprint_rotation && self.fingerprint_rotation_interval == 0 {
            return Err("fingerprint rotation requires fingerprint_rotation_interval > 0".into());
        }
        if self.enable_fingerprint_rotation
            && matches!(self.fingerprint_rotation_mode, RotationMode::Slots)
            && self.fingerprint_rotation_profiles.is_empty()
        {
            return Err("slots rotation requires at least one profile slot".into());
        }
        if matches!(self.mode, StealthMode::Intelligent) && !self.dynamic_enabled {
            return Err("intelligent mode requires dynamic_enabled to remain enabled".into());
        }
        if matches!(self.mode, StealthMode::Performance)
            && (self.enable_timing_obfuscation
                || self.enable_traffic_padding
                || self.enable_realtime_choke)
        {
            return Err(
                "performance mode cannot enable timing obfuscation/padding/realtime choke".into()
            );
        }
        if matches!(self.mode, StealthMode::Off)
            && (self.enable_http3_masquerading
                || self.use_qpack_headers
                || self.enable_domain_fronting
                || self.enable_traffic_padding
                || self.enable_timing_obfuscation
                || self.enable_protocol_mimicry
                || self.enable_realtime_choke
                || self.dynamic_enabled
                || self.enable_server_push_cover)
        {
            return Err("off mode cannot enable stealth transport/runtime features".into());
        }
        if self.enable_domain_fronting
            && self.fronting_domains.is_empty()
            && !matches!(self.mode, StealthMode::AntiDpi)
        {
            log::warn!(
                "domain fronting is enabled without fronting_domains; it will be disabled outside Anti-DPI"
            );
        }
        if !self.use_tls_cover {
            // Informative notice: TLS Cover extras are automatically disabled
            // (CertChainEmulator, cover PSK/tickets). Real TLS path remains fully active.
            log::warn!(
                "TLS Cover extras disabled: synthetic cert chain and cover PSK are not used"
            );
        }
        Ok(())
    }

    /// Applies environment variable overrides for stealth settings.
    /// Supported variables:
    /// - QUICFUSCATE_BROWSER / QUICFUSCATE_BROWSER_PROFILE: chrome|firefox|safari|edge (case-insensitive)
    /// - QUICFUSCATE_OS / QUICFUSCATE_OS_PROFILE: windows|linux|macos|android|ios (case-insensitive)
    /// - QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION: 0|1|true|false
    /// - QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE: 0|1|true|false
    /// - QUICFUSCATE_USE_TLS_COVER_EXTRAS: 0|1|true|false
    /// - QUICFUSCATE_DOH / QUICFUSCATE_DOH_ENABLED: 0|1|true|false
    /// - QUICFUSCATE_DOH_PROVIDER: URL
    /// - QUICFUSCATE_FRONTING: 0|1|true|false
    /// - QUICFUSCATE_FRONTING_DOMAINS: comma-separated domain list
    /// - QUICFUSCATE_H3_MASQUERADE: 0|1|true|false
    /// - QUICFUSCATE_QPACK: 0|1|true|false
    /// - QUICFUSCATE_STEALTH_PADDING: 0|1|true|false
    /// - QUICFUSCATE_STEALTH_PADDING_MAX / QUICFUSCATE_STEALTH_MAX_PADDING: integer bytes
    /// - QUICFUSCATE_STEALTH_PADDING_STRATEGY / QUICFUSCATE_PADDING_STRATEGY: random|fixed|adaptive|browser|browser-mimic|1|2|3|4
    /// - QUICFUSCATE_FINGERPRINT_ROTATION: 0|1|true|false
    /// - QUICFUSCATE_FINGERPRINT_ROTATION_INTERVAL: integer seconds
    /// - QUICFUSCATE_SERVER_PUSH_COVER: 0|1|true|false
    /// - QUICFUSCATE_SERVER_PUSH_INTENSITY: float
    /// - QUICFUSCATE_SERVER_PUSH_BASE_PATH: path
    /// - QUICFUSCATE_SERVER_PUSH_BURST_INTERVAL: integer seconds
    pub fn apply_env_overrides(&mut self) {
        let environment = crate::env_utils::EnvSnapshot::capture();
        self.apply_env_overrides_with_snapshot(&environment);
    }

    pub(crate) fn apply_env_overrides_with_snapshot(
        &mut self,
        environment: &crate::env_utils::EnvSnapshot,
    ) {
        // Primary mode override first (sets a known baseline)
        if let Some(v) = Self::env_first(environment, ["QUICFUSCATE_STEALTH_MODE"]) {
            let m = v.trim().to_ascii_lowercase();
            *self = match m.as_str() {
                "base" | "performance" => StealthConfig::performance(),
                "stealth" => StealthConfig::stealth(),
                "anti-dpi" | "antidpi" | "stealthmax" | "stealth-max" => StealthConfig::anti_dpi(),
                "dynamic" | "intelligent" | "auto" => StealthConfig::intelligent(),
                "manual" => StealthConfig::manual(),
                "off" => StealthConfig::off(),
                _ => {
                    log::warn!("Unknown QUICFUSCATE_STEALTH_MODE='{}' - ignoring", m);
                    self.clone()
                }
            };
        }

        if let Some(bp) = environment.first_with(
            ["QUICFUSCATE_BROWSER", "QUICFUSCATE_BROWSER_PROFILE"],
            Self::parse_browser,
        ) {
            self.initial_browser = bp;
        }
        if let Some(os) = environment.first_with(
            ["QUICFUSCATE_OS", "QUICFUSCATE_OS_PROFILE"],
            Self::parse_os,
        ) {
            self.initial_os = os;
        }
        if let Some(b) =
            Self::env_bool_first(environment, ["QUICFUSCATE_NETWORK_FINGERPRINT_NORMALIZATION"])
        {
            self.enable_network_fingerprint_normalization = b;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_SUPPRESS_ICMP_UNREACHABLE"])
        {
            self.suppress_icmp_unreachable = b;
        }
        if let Some(b) =
            Self::env_bool_first(
                environment,
                ["QUICFUSCATE_USE_TLS_COVER_EXTRAS", "QUICFUSCATE_USE_TLS_COVER"],
            )
        {
            self.use_tls_cover = b;
        }
        if let Some(b) = Self::env_bool_first(
            environment,
            ["QUICFUSCATE_DOH", "QUICFUSCATE_DOH_ENABLED"],
        ) {
            self.enable_doh = b;
        }
        if let Some(v) = Self::env_first(environment, ["QUICFUSCATE_DOH_PROVIDER"]) {
            self.doh_provider = v;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_FRONTING"]) {
            self.enable_domain_fronting = b;
        }
        if let Some(domains) = Self::env_csv_first(environment, ["QUICFUSCATE_FRONTING_DOMAINS"]) {
            self.fronting_domains = domains;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_H3_MASQUERADE"]) {
            self.enable_http3_masquerading = b;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_QPACK"]) {
            self.use_qpack_headers = b;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_STEALTH_PADDING"]) {
            self.enable_traffic_padding = b;
        }
        if let Some(n) = Self::env_parse_first(environment, [
            "QUICFUSCATE_STEALTH_PADDING_MAX",
            "QUICFUSCATE_STEALTH_MAX_PADDING",
        ]) {
            self.max_padding_size = n;
        }
        if let Some(strategy) = self.transport_padding_strategy_override(environment) {
            self.padding_strategy = strategy;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_FINGERPRINT_ROTATION"]) {
            self.enable_fingerprint_rotation = b;
        }
        if let Some(n) = Self::env_parse_first(environment, ["QUICFUSCATE_FINGERPRINT_ROTATION_INTERVAL"]) {
            self.fingerprint_rotation_interval = n;
        }

        // Compression policy overrides
        let mut pol = crate::compress::global_policy_with_snapshot(environment);
        Self::apply_compression_env_overrides(&mut pol, environment);
        crate::compress::set_global_policy(pol);

        // Optional fine-grained overrides
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_CHOKE_ENABLE"]) {
            self.enable_realtime_choke = b;
        }
        if let Some(n) = Self::env_parse_first(environment, ["QUICFUSCATE_CHOKE_TARGET_MBPS"]) {
            self.choke_target_mbps = n;
        }
        if let Some(n) = Self::env_parse_first(environment, ["QUICFUSCATE_CHOKE_BURST_MS"]) {
            self.choke_burst_ms = n;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_STEALTH_DYNAMIC"]) {
            self.dynamic_enabled = b;
        }
        if let Some(b) = Self::env_bool_first(environment, ["QUICFUSCATE_SERVER_PUSH_COVER"]) {
            self.enable_server_push_cover = b;
        }
        if let Some(n) = Self::env_f32_first(environment, ["QUICFUSCATE_SERVER_PUSH_INTENSITY"]) {
            if (0.0..=1.0).contains(&n) {
                self.server_push_intensity = n;
            } else {
                log::warn!(
                    "QUICFUSCATE_SERVER_PUSH_INTENSITY must be between 0.0 and 1.0; ignoring override"
                );
            }
        }
        if let Some(v) = Self::env_first(environment, ["QUICFUSCATE_SERVER_PUSH_BASE_PATH"]) {
            self.server_push_base_path = v;
        }
        if let Some(n) = Self::env_parse_first(environment, ["QUICFUSCATE_SERVER_PUSH_BURST_INTERVAL"]) {
            self.server_push_burst_interval = n;
        }
        self.normalize_protocol_mimicry_bundle();
    }

    fn parse_browser(s: &str) -> Option<BrowserProfile> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chrome" => Some(BrowserProfile::Chrome),
            "firefox" => Some(BrowserProfile::Firefox),
            "safari" => Some(BrowserProfile::Safari),
            "edge" => Some(BrowserProfile::Edge),
            _ => None,
        }
    }

    fn parse_os(s: &str) -> Option<OsProfile> {
        match s.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" => Some(OsProfile::Windows),
            "linux" => Some(OsProfile::Linux),
            "mac" | "macos" | "darwin" => Some(OsProfile::MacOS),
            "android" => Some(OsProfile::Android),
            "ios" => Some(OsProfile::IOS),
            _ => None,
        }
    }
}
