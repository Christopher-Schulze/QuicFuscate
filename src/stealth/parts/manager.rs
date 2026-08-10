/// The main stealth manager that coordinates all obfuscation techniques.
pub struct StealthManager {
    config: StealthConfig,
    /// Monotonic clock shared by every protocol-facing stealth child.
    clock: crate::time_source::ProtocolClock,
    /// Immutable environment generation used by this runtime owner.
    env_snapshot: Arc<crate::env_utils::EnvSnapshot>,
    fingerprint: Arc<Mutex<FingerprintProfile>>,
    domain_fronting: Option<DomainFrontingManager>,
    /// Cryptographic manager for key derivation.
    _crypto_manager: Arc<CryptoManager>,
    /// Last rotation timestamp
    last_rotation: Arc<Mutex<std::time::Instant>>,
    /// Browser/OS profile pool for rotation
    profile_pool: Arc<Vec<(BrowserProfile, OsProfile)>>,
    /// Current profile index for rotation
    profile_index: Arc<AtomicUsize>,
    /// Active probe detector
    probe_detector: Option<ActiveProbeDetector>,
    /// Flow shaper for jitter and dummy retransmits
    flow_shaper: Option<FlowShaper>,
    /// Cover traffic scheduler
    cover_traffic: Option<CoverTrafficScheduler>,
    /// Escalation flag after probe detection
    escalated: AtomicBool,
    /// Escalation timeout
    escalated_until: Arc<Mutex<Option<std::time::Instant>>>,
    /// Prefer MASQUE path while escalated (when available)
    prefer_masque: AtomicBool,
    /// Optional real-time rate choker
    rate_choker: Arc<Mutex<Option<RateChoker>>>,
    /// **NEW**: Server Push Cover Traffic state
    server_push_state: Arc<Mutex<ServerPushState>>,
    /// **NEW**: Runtime toggle for Server Push cover (used by Intelligent mode)
    server_push_runtime_enabled: std::sync::atomic::AtomicBool,
    /// Probe hits counter (Dynamic escalation heuristic)
    probe_hits: Arc<AtomicUsize>,
    /// Probe-count-based escalation state machine (TODO-416).
    escalation_state: Arc<EscalationState>,
    /// Connection-local Brain/probe level state.
    intelligent_level_hints: Arc<qf_transport_types::IntelligentLevelHints>,
    /// Runtime override: padding rate 0-100 (set on probe detection or escalation).
    /// Level 0 = 0%, Level 1 = 50%, Level 2 = 100%.
    runtime_padding_rate: AtomicU8,
    /// Runtime override: timing obfuscation rate 0-100 (set on probe detection or escalation).
    /// Level 0 = 0%, Level 1 = 0%, Level 2 = 100%.
    runtime_timing_rate: AtomicU8,
    /// Runtime override retained for telemetry/compatibility. Active fingerprint
    /// rotation is intentionally kept at 0 for established connections; persona
    /// changes are deferred to future sessions.
    runtime_rotation_rate: AtomicU8,
    /// Optimization manager for memory pools
    _optimization_manager: Arc<OptimizationManager>,
    /// Reality Fallback Proxy for active probe handling
    pub(crate) reality_proxy: Option<Arc<crate::reality::RealityProxy>>,
    /// Receiver for upstream responses (Reality Fallback)
    pub(crate) fallback_rx:
        Arc<Mutex<tokio::sync::mpsc::Receiver<crate::reality::FallbackResponse>>>,
    /// Cover handshake cache for reality-grade TLS mimikry (TODO-415).
    /// When enabled, holds cached TLS handshake material from a cover site
    /// that can be replayed to probes for byte-identical mimikry.
    pub(crate) cover_cache: Option<Arc<crate::reality::CoverHandshakeCache>>,
    /// Shared runtime owner for background Reality and profile workers.
    _background_owner: Option<Arc<StealthRuntimeOwner>>,
    /// Next scheduled cover PING emission time
    next_cover_ping: parking_lot::Mutex<std::time::Instant>,
}

impl StealthManager {
    /// Creates a new stealth manager with the given configuration.
    pub fn new(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
    ) -> Self {
        Self::new_internal(
            config,
            optimization_manager,
            crypto_manager,
            None,
            crate::time_source::ProtocolClock::default(),
        )
    }

    /// Creates a stealth manager attached to an explicit runtime owner.
    pub fn new_with_runtime_owner(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
    ) -> Self {
        Self::new_with_runtime_owner_and_clock(
            config,
            optimization_manager,
            crypto_manager,
            runtime_owner,
            crate::time_source::ProtocolClock::default(),
        )
    }

    /// Creates a stealth manager attached to an explicit runtime and protocol clock.
    pub fn new_with_runtime_owner_and_clock(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        clock: crate::time_source::ProtocolClock,
    ) -> Self {
        Self::new_internal(
            config,
            optimization_manager,
            crypto_manager,
            runtime_owner,
            clock,
        )
    }

    fn new_internal(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        clock: crate::time_source::ProtocolClock,
    ) -> Self {
        let env_snapshot = Arc::new(crate::env_utils::EnvSnapshot::capture());
        let fingerprint = Arc::new(Mutex::new(FingerprintProfile::new_with_snapshot(
            config.initial_browser,
            config.initial_os,
            &env_snapshot,
        )));

        let domain_fronting = Self::domain_fronting_for_config(&config);

        let profile_pool = Arc::new(config.rotation_profile_slots());

        let probe_detector = if config.dynamic_enabled
            || config.enable_traffic_padding
            || config.enable_timing_obfuscation
        {
            Some(ActiveProbeDetector::new_with_clock(5, ProbeResponseMode::Switch, &clock))
        } else {
            None
        };

        // FlowShaper is the primary heavy timing owner for Anti-DPI and
        // escalation-only paths. Light Stealth timing stays on the transport
        // timing gate.
        let flow_shaper = if config.enable_timing_obfuscation || config.dynamic_enabled {
            let jitter_us = if matches!(config.mode, StealthMode::AntiDpi) { 3000 } else { 750 };
            Some(FlowShaper::new_with_clock(
                jitter_us,
                matches!(config.mode, StealthMode::AntiDpi),
                &clock,
            ))
        } else {
            None
        };

        // Initialize cover traffic scheduler only for modes that intentionally
        // emit H3 cover requests. Performance keeps H3/QPACK persona active
        // but must not generate extra cover traffic on the clean path.
        let cover_traffic = if Self::cover_traffic_scheduler_allowed(&config) {
            // Use the fronted domain or fallback to a CDN domain
            let target = if let Some(ref df) = domain_fronting {
                df.get_fronted_domain()
            } else {
                "cdn.cloudflare.com".to_string()
            };
            Some(CoverTrafficScheduler::new_with_clock(target, 5000, &clock)) // 5 second interval
        } else {
            None
        };

        // Initialize rate choker (disabled in Base, enabled in Anti-DPI; Dynamic activates on demand)
        let rate_choker = Arc::new(Mutex::new(RateChoker::new_with_clock(
            config.choke_target_mbps,
            config.choke_burst_ms,
            &clock,
        )));

        // Initialize Server Push Cover Traffic state
        let server_push_state = Arc::new(Mutex::new(ServerPushState::new_with_clock(
            &clock,
            config.server_push_intensity,
        )));

        // REALITY PROXY INITIALIZATION
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let reality_proxy = if config.dynamic_enabled {
            // Enable Reality if Dynamic mode is on
            Some(Arc::new(crate::reality::RealityProxy::new_with_snapshot(
                tx,
                &env_snapshot,
            )))
        } else {
            None
        };

        if let (Some(owner), Some(proxy)) = (runtime_owner.as_ref(), reality_proxy.as_ref()) {
            owner.register_reality_proxy(proxy);
        }

        if reality_proxy.is_some() {
            log::info!("Reality Proxy (Reverse Proxy) initialized for Active Probe fallback.");
        }

        // COVER HANDSHAKE CACHE INITIALIZATION (TODO-415)
        // Runtime-owned managers share one cache. Direct constructors keep a
        // local cache without spawning an unowned worker.
        let cover_cache = runtime_owner
            .as_ref()
            .and_then(|owner| owner.cover_cache())
            .or_else(|| {
                let reality_config =
                    crate::reality::RealityConfig::from_env_with_snapshot(&env_snapshot);
                if reality_config.enabled {
                    log::info!(
                        "Cover handshake cache initialized for {} (TTL={}s) without a runtime worker",
                        reality_config.cover_host,
                        reality_config.cache_ttl
                    );
                    Some(Arc::new(crate::reality::CoverHandshakeCache::new(reality_config)))
                } else {
                    None
                }
            });

        let intelligent_level_hints = Arc::new(qf_transport_types::IntelligentLevelHints::new());

        Self {
            config,
            clock: clock.clone(),
            env_snapshot: Arc::clone(&env_snapshot),
            fingerprint,
            domain_fronting,
            _crypto_manager: crypto_manager,
            last_rotation: Arc::new(Mutex::new(clock.now())),
            profile_pool,
            profile_index: Arc::new(AtomicUsize::new(0)),
            probe_detector,
            flow_shaper,
            cover_traffic,
            escalated: AtomicBool::new(false),
            escalated_until: Arc::new(Mutex::new(None)),
            prefer_masque: AtomicBool::new(false),
            rate_choker,
            server_push_state,
            server_push_runtime_enabled: std::sync::atomic::AtomicBool::new(false),
            probe_hits: Arc::new(AtomicUsize::new(0)),
            escalation_state: Arc::new(EscalationState::new(
                Arc::clone(&intelligent_level_hints),
                &env_snapshot,
            )),
            intelligent_level_hints,
            runtime_padding_rate: AtomicU8::new(0),
            runtime_timing_rate: AtomicU8::new(0),
            runtime_rotation_rate: AtomicU8::new(0),
            _optimization_manager: optimization_manager,
            reality_proxy,
            fallback_rx: Arc::new(Mutex::new(rx)),
            cover_cache,
            _background_owner: runtime_owner,
            next_cover_ping: parking_lot::Mutex::new(clock.now()),
        }
    }

    fn domain_fronting_for_config(config: &StealthConfig) -> Option<DomainFrontingManager> {
        if !config.enable_domain_fronting {
            return None;
        }
        if !config.fronting_domains.is_empty() {
            return Some(DomainFrontingManager::new(config.fronting_domains.clone()));
        }
        if matches!(config.mode, StealthMode::AntiDpi) {
            return Some(DomainFrontingManager::ultra_stealth());
        }
        warn!(
            "Domain fronting requested without configured fronting domains outside Anti-DPI - disabling for a coherent H3 persona"
        );
        None
    }

    /// Debug consistency check: validates TLS fingerprint matches header profile.
    #[cfg(debug_assertions)]
    pub fn validate_profile_consistency(&self, tls_profile_name: &str) {
        let fingerprint = self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let expected_browser = match fingerprint.browser {
            BrowserProfile::Chrome => "chrome",
            BrowserProfile::Firefox => "firefox",
            BrowserProfile::Safari => "safari",
            BrowserProfile::Edge => "edge",
        };

        let expected_os = match fingerprint.os {
            OsProfile::Windows => "windows",
            OsProfile::MacOS => "macos",
            OsProfile::Linux => "linux",
            OsProfile::Android => "android",
            OsProfile::IOS => "ios",
        };

        if !tls_profile_name.to_lowercase().contains(expected_browser) {
            debug!(
                "Profile consistency warning: TLS profile '{}' may not match browser '{}'",
                tls_profile_name, expected_browser
            );
        }

        if !tls_profile_name.to_lowercase().contains(expected_os) {
            debug!(
                "Profile consistency warning: TLS profile '{}' may not match OS '{}'",
                tls_profile_name, expected_os
            );
        }

        // Validate sec-ch-ua consistency for Chromium browsers
        if matches!(fingerprint.browser, BrowserProfile::Chrome | BrowserProfile::Edge) {
            let masquerade = Http3Masquerade::new(fingerprint.clone());
            let sec_ch_ua = masquerade.build_sec_ch_ua();
            let ua = &fingerprint.user_agent;

            // Extract version from both and compare
            if let (Some(ua_ver), Some(ch_ver)) = (
                masquerade
                    .extract_major_version(ua, "Chrome")
                    .or_else(|| masquerade.extract_major_version(ua, "Edg")),
                masquerade
                    .extract_major_version(&sec_ch_ua, "Chrome")
                    .or_else(|| masquerade.extract_major_version(&sec_ch_ua, "Edge")),
            ) {
                if ua_ver != ch_ver {
                    debug!(
                        "Profile consistency warning: UA version {} != sec-ch-ua version {}",
                        ua_ver, ch_ver
                    );
                }
            }
        }

        debug!("Profile consistency check completed for {}/{}", expected_browser, expected_os);
    }

    /// Advances the next-session persona cursor when rotation policy is due.
    ///
    /// Active connections keep a frozen Browser/OS/TLS/H3 persona for their
    /// lifetime. Mid-session identity changes are more fingerprintable than a
    /// stable browser session because TLS, QUIC transport params, QPACK headers,
    /// and user-agent state would no longer agree. Rotation therefore only
    /// updates bookkeeping for future connection selection and never mutates
    /// `self.fingerprint`.
    pub fn maybe_rotate_fingerprint(&self) {
        let escalated = self.escalated.load(Ordering::Relaxed);
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);
        let mode_allows = match self.config.fingerprint_rotation_mode {
            RotationMode::Fixed => false,
            RotationMode::Slots | RotationMode::All => self.config.enable_fingerprint_rotation,
        };
        let runtime_override = self.runtime_rotation_rate.load(Ordering::Relaxed) > 50;
        let effective_enable = mode_allows || (anti_mode && escalated) || runtime_override;
        if !effective_enable {
            return;
        }

        let interval =
            if anti_mode && escalated { 30 } else { self.config.fingerprint_rotation_interval };
        if interval == 0 {
            return;
        }

        let now = self.clock.now();
        let should_rotate = {
            let last = self.last_rotation.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            self.clock.elapsed_since(*last).as_secs() >= interval
        };

        if should_rotate {
            if let Some(pool_len) = (!self.profile_pool.is_empty()).then_some(self.profile_pool.len()) {
                self.profile_index
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |index| {
                        Some((index + 1) % pool_len)
                    })
                    .ok();
            }
            *self.last_rotation.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = now;
            debug!("Deferred fingerprint rotation to the next connection; active persona remains frozen");
        }
    }

    /// Returns the selected persona for the next connection.
    ///
    /// The active connection keeps its original fingerprint. Callers that
    /// create a new connection may use this snapshot after a rotation tick.
    pub fn next_session_profile(&self) -> Option<FingerprintProfile> {
        let pool_len = self.profile_pool.len();
        if pool_len == 0 {
            return None;
        }
        let index = self.profile_index.load(Ordering::Acquire) % pool_len;
        let (browser, os) = self.profile_pool[index];
        Some(FingerprintProfile::new(browser, os))
    }

    /// Returns a clone of the current fingerprint profile for TLS/ALPN mapping.
    fn current_fingerprint(&self) -> FingerprintProfile {
        match self.fingerprint.lock() {
            Ok(g) => g.clone(),
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner().clone()
            }
        }
    }

    /// Builds a TLS profile from the current fingerprint, optionally overriding SNI.
    pub(crate) fn runtime_tls_profile(
        &self,
        sni_override: Option<&str>,
    ) -> crate::qftls::TlsProfile {
        let fingerprint = self.current_fingerprint();
        let mut profile = crate::qftls::profile_from_fingerprint(&fingerprint);
        if let Some(sni) = sni_override {
            profile.sni = Some(sni.to_string());
        }
        profile.cover_performance_mode = matches!(
            self.config.mode,
            StealthMode::Off | StealthMode::Performance | StealthMode::Intelligent
        );
        if profile.cover_performance_mode {
            profile.timing_jitter = None;
        }
        profile
    }

    /// Returns QPACK (max_table_capacity, max_blocked_streams) tuned per browser profile.
    pub(crate) fn qpack_runtime_profile(&self) -> (u64, u64) {
        let fingerprint = self.current_fingerprint();
        match fingerprint.browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => (64u64 * 1024u64, 16u64),
            BrowserProfile::Firefox | BrowserProfile::Safari => (32u64 * 1024u64, 8u64),
        }
    }

    /// Returns the browser-specific QPACK static header index subset.
    pub(crate) fn qpack_index_policy(&self) -> &'static [&'static [u8]] {
        let fingerprint = self.current_fingerprint();
        match fingerprint.browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &[
                b":authority",
                b":path",
                b":method",
                b"content-type",
                b"accept-encoding",
                b"user-agent",
                b"accept",
                b"cache-control",
            ],
            BrowserProfile::Firefox => {
                &[b":authority", b":path", b":method", b"content-type", b"accept-language"]
            }
            BrowserProfile::Safari => &[b":authority", b":path", b":method", b"content-type"],
        }
    }

    /// Returns a human-readable "Browser/OS" label for the active fingerprint.
    pub(crate) fn current_persona_name(&self) -> String {
        let fingerprint = self.current_fingerprint();
        format!("{:?}/{:?}", fingerprint.browser, fingerprint.os)
    }

    /// Applies the configured browser/OS persona's QUIC parameters to the
    /// transport configuration. Rustls owns the real wire ClientHello.
    pub(crate) fn apply_utls_profile(&self, config: &mut crate::transport::Config) {
        let fingerprint = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
        info!("Applying uTLS fingerprint for: {:?}/{:?}", fingerprint.browser, fingerprint.os);

        if let Err(e) = config.set_application_protos(crate::transport::h3::APPLICATION_PROTOCOL) {
            warn!("Failed to set HTTP/3 application protos: {}", e);
        }

        // Apply the detailed QUIC transport parameters from the harmonized profile.
        config.set_initial_max_data(fingerprint.initial_max_data);
        config
            .set_initial_max_stream_data_bidi_local(fingerprint.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(
            fingerprint.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_streams_bidi(fingerprint.initial_max_streams_bidi);
        config.set_max_idle_timeout(fingerprint.max_idle_timeout);

        // Chrome-like ACK policy tuned per browser profile.
        // Reuse the already-held `fingerprint` guard: re-locking the same
        // non-reentrant mutex here would deadlock (the guard acquired above is
        // still in scope until the end of this function).
        let browser_profile = fingerprint.browser;
        match browser_profile {
            BrowserProfile::Chrome | BrowserProfile::Edge => {
                config.set_ack_eliciting_threshold(2);
                config.set_max_ack_delay(25);
                config.set_ack_delay_exponent(3);
            }
            BrowserProfile::Firefox => {
                config.set_ack_eliciting_threshold(2);
                config.set_max_ack_delay(20);
                config.set_ack_delay_exponent(3);
            }
            BrowserProfile::Safari => {
                config.set_ack_eliciting_threshold(3);
                config.set_max_ack_delay(30);
                config.set_ack_delay_exponent(3);
            }
        }
        // Anti-DPI: prefer external pacing (RateChoker/Stealth layer), avoid double sleeps in transport
        if matches!(self.config.mode, StealthMode::AntiDpi) {
            config.set_external_pacing(true);
        }

        // ENV overrides (advanced tuning)
        if let Some(n) = self.config.transport_ack_threshold_override(&self.env_snapshot) {
            config.set_ack_eliciting_threshold(n);
        }
        if let Some(ms) = self.config.transport_ack_max_delay_override(&self.env_snapshot) {
            config.set_max_ack_delay(ms);
        }
        if let Some(enabled) =
            self.config.transport_external_pacing_override(&self.env_snapshot)
        {
            config.set_external_pacing(enabled);
        }

        // Apply stealth padding knobs to transport config so Connection::send() can pad before sealing
        let strategy_code = match self.config.padding_strategy {
            PaddingStrategy::Random => 1,
            PaddingStrategy::Fixed => 2,
            PaddingStrategy::Adaptive => 3,
            PaddingStrategy::BrowserMimic => 4,
            PaddingStrategy::PacketNormalize => 5,
        };
        config.set_stealth_padding(
            self.config.enable_traffic_padding,
            strategy_code,
            self.config.max_padding_size,
        );
        if self.config.padding_strategy == PaddingStrategy::PacketNormalize
            && self.config.normalize_target_size > 0
        {
            config.set_stealth_normalize_target(self.config.normalize_target_size);
        }
        // Set default adaptive granularity (bytes) - sensible default 64
        config.set_stealth_adaptive_granularity(64);
        // Set default BrowserMimic bias from active fingerprint
        let bias_default = match (fingerprint.browser, fingerprint.os) {
            (BrowserProfile::Safari, _) | (_, OsProfile::IOS) => 1,
            (BrowserProfile::Firefox, OsProfile::Linux) => 2,
            (_, OsProfile::Android) => 4,
            _ => 3,
        };
        config.set_stealth_mimic_bias(bias_default);

        // Apply stealth timing knobs (simple per-packet jitter in microseconds)
        // Defaults: Stealth (no rotation) ~750us; StealthMax (rotation on) ~3000us.
        if self.config.enable_timing_obfuscation {
            let default_us = if self.config.enable_fingerprint_rotation { 3000 } else { 750 };
            config.set_stealth_timing(true, default_us);
        } else {
            config.set_stealth_timing(false, 0);
        }

        // ENV overrides (optional):
        // - QUICFUSCATE_STEALTH_PADDING_MAX = <usize>
        // - QUICFUSCATE_STEALTH_PADDING_STRATEGY = random|fixed|adaptive|browser|1..4
        // - QUICFUSCATE_STEALTH_JITTER_US = <u32>
        if let Some(v) = self.config.transport_padding_max_override(&self.env_snapshot) {
            config.set_stealth_padding(self.config.enable_traffic_padding, strategy_code, v);
        }
        if let Some(strategy) =
            self.config.transport_padding_strategy_override(&self.env_snapshot)
        {
            let scode = match strategy {
                PaddingStrategy::Random => 1,
                PaddingStrategy::Fixed => 2,
                PaddingStrategy::Adaptive => 3,
                PaddingStrategy::BrowserMimic => 4,
                PaddingStrategy::PacketNormalize => 5,
            };
            config.set_stealth_padding(
                self.config.enable_traffic_padding,
                scode,
                self.config.max_padding_size,
            );
        }
        if let Some(us) = self.config.transport_jitter_override_us(&self.env_snapshot) {
            if us > 0 {
                config.set_stealth_timing(true, us);
            } else {
                config.set_stealth_timing(false, 0);
            }
        }
        if let Some(gran) =
            self.config.transport_adaptive_granularity_override(&self.env_snapshot)
        {
            config.set_stealth_adaptive_granularity(gran);
        }
        if let Some(code) = self.config.transport_mimic_bias_override(&self.env_snapshot) {
            config.set_stealth_mimic_bias(code);
        } else {
            config.set_stealth_mimic_bias(bias_default);
        }
    }

    /// Returns the SNI and Host header values for a connection.
    /// Applies domain fronting if enabled.
    pub(crate) fn get_connection_headers(&self, real_host: &str) -> (String, String) {
        if self.config.enable_domain_fronting {
            if let Some(df) = self.domain_fronting.as_ref() {
                let fronted_domain = df.get_fronted_domain();
                debug!("Domain fronting enabled. SNI: {}, Host: {}", fronted_domain, real_host);
                return (fronted_domain, real_host.to_string());
            }
        }
        (real_host.to_string(), real_host.to_string())
    }

    /// Processes an outgoing packet payload, applying configured stealth techniques.
    /// Returns an optional delay Duration if the packet should be delayed (Async Scheduler).
    /// Does NOT block the thread.
    pub(crate) fn process_outgoing_packet(
        &self,
        _payload: &mut [u8],
    ) -> Option<std::time::Duration> {
        // Shaping delays are merged in core::QuicFuscateConnection::send() with transport
        // jitter (when active). One release gate: next_packet_release.
        // - explicit realtime choke -> RateChoker
        // - Anti-DPI without choke -> FlowShaper
        let mut total_delay = std::time::Duration::ZERO;
        let mut choked_bytes = 0u64;
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);

        if self.config.enable_realtime_choke {
            if let Ok(mut guard) = self.rate_choker.lock() {
                if let Some(choker) = guard.as_mut() {
                    let len = _payload.len();
                    if len > 0 {
                        total_delay = choker.shape(len);
                        if !total_delay.is_zero() {
                            choked_bytes = len as u64;
                        }
                    }
                }
            }
        } else if anti_mode {
            if let Some(flow_shaper) = &self.flow_shaper {
                total_delay = flow_shaper.apply_jitter() + flow_shaper.apply_flight_pacing(false);
            }
        }

        // Telemetry for calculated delay (Async Mode)
        if !total_delay.is_zero() {
            // We count this as "sleep" even if we yield async
            let ms = total_delay.as_millis() as u64;
            crate::telemetry::CHOKE_SLEEP_MS.inc_by(ms);
            if choked_bytes > 0 {
                crate::telemetry::CHOKED_BYTES.inc_by(choked_bytes);
            }
        }

        // Record packet into history to consume PacketInfo fields
        if anti_mode {
            if let Some(shaper) = &self.flow_shaper {
                let ty = if choked_bytes == 0 {
                    StealthPacketClass::Data
                } else {
                    StealthPacketClass::Retransmit
                };
                shaper.record_and_prune(_payload.len(), ty);
            }
        }

        // If escalated due to probing, temporarily apply stronger pacing
        if self.escalated.load(Ordering::Relaxed) {
            // Check timeout
            let mut clear_flag = false;
            if let Ok(mut guard) = self.escalated_until.lock() {
                if let Some(deadline) = *guard {
                    if self.clock.now() >= deadline {
                        *guard = None;
                        clear_flag = true;
                    }
                }
            }
            if clear_flag {
                self.escalated.store(false, Ordering::Relaxed);
                // Restore default cover-traffic interval (5s) and MASQUE preference
                if let Some(ref sched) = self.cover_traffic {
                    sched.set_interval_ms(5000);
                }
                self.prefer_masque.store(false, Ordering::Relaxed);
            }
        }

        if total_delay.is_zero() {
            None
        } else {
            Some(total_delay)
        }

        // IMPORTANT: Do not mutate sealed QUIC datagrams here.
        // Timing/flow shaping is allowed (sleep), but payload bytes must remain intact
        // to preserve AEAD integrity and FEC compatibility.

        // Note: Padding is applied at a higher level before this function
        // HTTP/3 Masquerading is applied at the stream level when sending data
    }

    /// Processes an incoming packet payload, reversing stealth techniques.
    pub(crate) fn process_incoming_packet(&self, payload: &mut [u8], source: std::net::SocketAddr) {
        // Check for active probing first (before deobfuscation)
        if let Some(detector) = &self.probe_detector {
            if let Some(response_mode) = detector.check_packet(payload, source) {
                warn!("Active probe detected from {} - response mode: {:?}", source, response_mode);
                telemetry!(crate::telemetry::STEALTH_PROBE_DETECTED.inc());

                // Handle probe response
                match response_mode {
                    ProbeResponseMode::Switch => {
                        telemetry!(crate::telemetry::STEALTH_PROBE_SWITCH.inc());
                        // Switch to higher stealth mode
                        self.on_probe_detected(source);
                    }
                    ProbeResponseMode::Fake => {
                        // Send fake response (handled elsewhere)
                        telemetry!(crate::telemetry::STEALTH_PROBE_FAKE.inc());
                        debug!("Fake response for probe from {}", source);
                    }
                    ProbeResponseMode::Block => {
                        // Block source (handled at connection level)
                        telemetry!(crate::telemetry::STEALTH_PROBE_BLOCK.inc());
                        info!("Blocking source {}", source);
                    }
                    ProbeResponseMode::Ignore => {
                        // Just log and continue
                        debug!("Ignoring probe from {}", source);
                    }
                }
            }
        }
        // IMPORTANT: Do not mutate sealed QUIC datagrams on RX either; keep bytes intact
        // for AEAD verification and FEC correctness.
    }

    /// Forwards to `process_incoming_packet` for test visibility.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn process_incoming_packet_for_test(
        &self,
        payload: &mut [u8],
        source: std::net::SocketAddr,
    ) {
        self.process_incoming_packet(payload, source);
    }

    /// Handles active probe detection using the gradual escalation state machine.
    ///
    /// Instead of immediately escalating to Level 2 on a single probe (the old
    /// binary behavior), this records the probe in `EscalationState` and only
    /// escalates if the configurable thresholds are met:
    /// - Level 0 → 1: ≥3 probes within 60 seconds.
    /// - Level 1 → 2: ≥8 probes within 120 seconds.
    ///
    /// A single probe is logged but does NOT trigger escalation.
    fn on_probe_detected(&self, source: std::net::SocketAddr) {
        warn!("Active probe detected from {}", source);
        // Dynamic/Performance policy: only escalate if Intelligent/Stealth was chosen.
        // Performance mode stays performance-focused and does not auto-escalate.
        let allow_escalation = self.config.dynamic_enabled;
        if !allow_escalation {
            info!("Probe detected in non-dynamic mode - not escalating (user preference: performance/stealth)");
            return;
        }

        // Increment probe hits counter for telemetry.
        let _hits = self.probe_hits.fetch_add(1, Ordering::Relaxed) + 1;

        // Record the probe in the escalation state machine and check thresholds.
        let new_level = self.escalation_state.record_probe();

        if let Some(level) = new_level {
            // Threshold met - escalate.
            info!("Stealth escalated to level {} due to probe pattern from {}", level, source);
            telemetry!(crate::telemetry::STEALTH_MODE_ESCALATED.inc());

            // Apply the graduated escalation.
            self.escalate_to_level(level);

            // Inject pressure into the Brain's signal_other bucket so the next
            // derive_intelligent_runtime_policy call aligns with the escalation.
            crate::optimize::telemetry::STEALTH_SIGNAL_OTHER.fetch_add(10, Ordering::Relaxed);

            // Mark escalated window for stronger pacing (Level 2 only).
            if level >= 2 {
                self.escalated.store(true, Ordering::Relaxed);
                if let Ok(mut guard) = self.escalated_until.lock() {
                    *guard = self
                        .clock
                        .checked_deadline_after(std::time::Duration::from_secs(20 * 60));
                }

                // Keep the active Browser/OS/TLS/H3 persona stable. Escalation
                // may raise padding, timing, cover traffic and MASQUE hints,
                // but it must not rotate fingerprints or fronting hosts inside
                // an already-established connection.

                // Anti-DPI mode with realtime choke: activate rate choker.
                let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);
                if anti_mode && self.config.enable_realtime_choke {
                    if let Ok(mut guard) = self.rate_choker.lock() {
                        *guard = RateChoker::new_with_clock(50, 12, &self.clock);
                    }
                }
            }
        } else {
            // Threshold not met - log but do not escalate.
            debug!(
                "Probe from {} recorded but escalation threshold not yet met (level={})",
                source,
                self.escalation_state.current_level()
            );
        }
    }

    /// Generates HTTP/3 headers for masquerading a request.
    /// Returns cover-traffic headers when a request is due (rate-limited), otherwise None.
    pub(crate) fn cover_headers_due(&self) -> Option<Vec<qf_transport_types::h3::Header>> {
        if self.server_push_cover_active() {
            return None;
        }
        if !self.cover_header_emission_allowed() {
            return None;
        }
        if let Some(ref sched) = self.cover_traffic {
            return sched.get_next_request();
        }
        None
    }

    fn cover_traffic_scheduler_allowed(config: &StealthConfig) -> bool {
        config.enable_http3_masquerading
            && !matches!(config.mode, StealthMode::Off | StealthMode::Performance)
    }

    fn cover_header_emission_allowed(&self) -> bool {
        match self.config.mode {
            StealthMode::Off | StealthMode::Performance => false,
            StealthMode::Intelligent => self.intelligent_runtime_level() >= 1,
            StealthMode::Stealth | StealthMode::AntiDpi | StealthMode::Manual => true,
        }
    }

    /// Returns a vector of HTTP/3 headers for a request.
    pub(crate) fn get_http3_header_list(
        &self,
        host: &str,
        path: &str,
    ) -> Option<Vec<qf_transport_types::h3::Header>> {
        if self.config.enable_http3_masquerading {
            let fp = match self.fingerprint.lock() {
                Ok(g) => g,
                Err(p) => {
                    warn!("fingerprint mutex poisoned; recovering");
                    p.into_inner()
                }
            };
            let fh = FakeHeaders::new(FakeHeadersConfig { optimize_for_quic: true }, fp.clone());
            Some(fh.header_list(host, path))
        } else {
            None
        }
    }

    /// Expose current mode (copy).
    pub fn mode(&self) -> StealthMode {
        self.config.mode
    }

    /// Returns true if the manager is running in Intelligent (adaptive) mode.
    pub(crate) fn is_intelligent_runtime(&self) -> bool {
        matches!(self.config.mode, StealthMode::Intelligent)
    }

    pub(crate) fn environment_snapshot(&self) -> Arc<crate::env_utils::EnvSnapshot> {
        Arc::clone(&self.env_snapshot)
    }

    /// Computes which transport knobs the brain is allowed to adjust at runtime.
    pub(crate) fn brain_runtime_permissions(&self) -> crate::transport::BrainRuntimePermissions {
        let ack_locked = self
            .config
            .transport_ack_threshold_override(&self.env_snapshot)
            .is_some()
            || self
                .config
                .transport_ack_max_delay_override(&self.env_snapshot)
                .is_some();
        let timing_locked = self
            .config
            .transport_external_pacing_override(&self.env_snapshot)
            .is_some()
            || self
                .config
                .transport_jitter_override_us(&self.env_snapshot)
                .is_some();
        let padding_locked = self
            .config
            .transport_padding_max_override(&self.env_snapshot)
            .is_some()
            || self
                .config
                .transport_padding_strategy_override(&self.env_snapshot)
                .is_some()
            || self
                .config
                .transport_adaptive_granularity_override(&self.env_snapshot)
                .is_some()
            || self
                .config
                .transport_mimic_bias_override(&self.env_snapshot)
                .is_some();
        let manual_transport_locked = ack_locked || timing_locked || padding_locked;

        crate::transport::BrainRuntimePermissions {
            ack_threshold: !ack_locked,
            external_pacing: !timing_locked,
            timing: !timing_locked,
            padding: !padding_locked,
            mimic_bias: !padding_locked,
            granularity: !padding_locked,
            cc_profile: !manual_transport_locked,
        }
    }

    /// Derives a concrete runtime stealth policy from brain-supplied signal inputs.
    pub(crate) fn derive_intelligent_runtime_policy(
        inputs: IntelligentStealthInputs,
    ) -> crate::transport::StealthRuntimePolicy {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::derive_intelligent_runtime_policy_with_snapshot(inputs, &environment)
    }

    pub(crate) fn derive_intelligent_runtime_policy_with_snapshot(
        inputs: IntelligentStealthInputs,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> crate::transport::StealthRuntimePolicy {
        let external_pacing = inputs.ce_ratio_recent < 0.01
            && inputs.ack_us < 8_000.0
            && inputs.rtt_spike_weight == 0.0;

        // Under congestion/DPI pressure: maximize jitter (85% of budget) to break timing analysis.
        // Clean-path external pacing: 60% (already optimal paced). Otherwise: 40% baseline.
        let base_jitter_hint = if external_pacing {
            (inputs.jitter_max_us as f64 * 0.6) as u32
        } else if inputs.ce_ratio_recent > 0.05 || inputs.rtt_spike_weight >= 4.0 {
            // Pressure detected: ramp up, not down - more randomization defeats timing fingerprints.
            (inputs.jitter_max_us as f64 * 0.85) as u32
        } else {
            (inputs.jitter_max_us as f64 * 0.4) as u32
        };

        let tos_anomaly = inputs.signal_tos > 0;
        // Level 0 clean path: disable padding entirely to keep Intelligent mode near-zero overhead
        // when there is no pressure. Only activate once signals warrant it (level >= 1 or any anomaly).
        let (padding_enabled, padding_strategy, padding_max) = if inputs.level_hint == 0
            && inputs.ce_ratio_recent < 0.01
            && inputs.signal_other == 0
            && !tos_anomaly
        {
            (false, 0u8, 0)
        } else if inputs.ce_ratio_recent > 0.08
            || inputs.reorder_ratio > 0.02
            || inputs.signal_other > 0
        {
            (true, 1u8, inputs.pad_max_low)
        } else if inputs.size_div + inputs.iat_div > 1.4 || tos_anomaly {
            (true, 3u8, inputs.pad_max_high.min(512))
        } else {
            (true, 4u8, inputs.pad_max_low)
        };

        let mimic_bias =
            if inputs.ce_ratio_recent > 0.05 || inputs.iat_div > 1.0 || inputs.signal_other > 0 {
                1
            } else if inputs.size_div > 1.0 {
                2
            } else if inputs.ack_us < 3_000.0 {
                4
            } else {
                3
            };

        let adaptive_granularity = if inputs.ce_ratio_recent > 0.10 || inputs.signal_other > 0 {
            32
        } else if inputs.ce_ratio_recent < 0.001 {
            128
        } else {
            64
        };

        let cc_profile = match mimic_bias {
            1 => crate::transport::recovery::BrowserProfile::Safari,
            2 => crate::transport::recovery::BrowserProfile::Firefox,
            4 => crate::transport::recovery::BrowserProfile::Edge,
            _ => crate::transport::recovery::BrowserProfile::Chrome,
        };

        // Gradual intensity rates from TODO-416: each level maps to a
        // percentage that controls what fraction of packets are padded
        // and how much jitter is applied.
        // Level 0: 0% padding, 0% timing
        // Level 1: 50% padding (configurable), 0% timing
        // Level 2: 100% padding, 100% timing
        let padding_rate = if !padding_enabled {
            0u8
        } else {
            match inputs.level_hint {
                0 => 0u8,
                1 => environment
                    .parse::<u8>("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1")
                    .unwrap_or(50),
                _ => 100u8,
            }
        };
        let timing_rate = match inputs.level_hint {
            0 | 1 => 0u8,
            _ => 100u8,
        };

        crate::transport::StealthRuntimePolicy {
            external_pacing,
            timing_enabled: !external_pacing,
            timing_max_jitter_us: base_jitter_hint,
            mimic_bias,
            adaptive_granularity,
            cc_profile,
            padding_enabled,
            padding_strategy,
            padding_max,
            padding_rate,
            timing_rate,
        }
    }

    /// Returns true if active stealth features (beyond Performance/Off) are engaged.
    #[cfg(feature = "orchestrator")]
    pub(crate) fn runtime_stealth_active(&self) -> bool {
        !matches!(self.config.mode, StealthMode::Performance | StealthMode::Off)
    }

    /// Enable/disable Server Push at runtime (Intelligent mode). Optionally adjust intensity.
    fn enable_server_push_runtime(&self, enabled: bool, intensity: Option<f32>) {
        self.server_push_runtime_enabled.store(enabled, Ordering::Relaxed);
        if let Some(i) = intensity {
            if let Ok(mut st) = self.server_push_state.lock() {
                st.current_intensity = i;
            }
        }
    }

    /// Applies orchestrator-driven server-push cover parameters.
    #[cfg(feature = "orchestrator")]
    pub(crate) fn sync_orchestrator_server_push_controls(
        &self,
        should_trigger: bool,
        intensity: f32,
    ) {
        if !should_trigger {
            return;
        }

        let clamped_intensity = intensity.clamp(0.0, 1.0);
        self.enable_server_push_runtime(
            true,
            Some(self.escalation_min_server_push_intensity(clamped_intensity)),
        );
    }

    fn escalation_min_server_push_intensity(&self, base_intensity: f32) -> f32 {
        if self.escalated.load(Ordering::Relaxed) {
            base_intensity.max(0.8)
        } else {
            base_intensity
        }
    }

    /// Returns the brain-computed Intelligent stealth escalation level (0 = inactive).
    pub(crate) fn intelligent_runtime_level(&self) -> u32 {
        if self.is_intelligent_runtime() {
            self.intelligent_level_hints.effective_level()
        } else {
            0
        }
    }

    /// Returns the connection-local level state shared with its Brain observer.
    pub(crate) fn intelligent_level_hints(&self) -> Arc<qf_transport_types::IntelligentLevelHints> {
        Arc::clone(&self.intelligent_level_hints)
    }

    /// Apply the brain-computed intelligent level to runtime overrides.
    /// Called periodically (e.g., from the connection tick) to sync runtime
    /// padding/timing/rotation rates with the brain's escalation level.
    /// Also checks probe-count-based de-escalation from `EscalationState`.
    /// Only active in Intelligent mode - explicit modes set their rates directly.
    pub(crate) fn sync_intelligent_level(&self) {
        if !self.is_intelligent_runtime() {
            return;
        }

        // Check if the quiet period has elapsed and de-escalate if so.
        // This runs on every tick so de-escalation happens promptly after
        // the quiet period expires, without waiting for the brain's next
        // policy cycle.
        if let Some(new_level) = self.escalation_state.check_de_escalation() {
            info!("Stealth de-escalated to level {} after quiet period", new_level);
            self.de_escalate_to_level(new_level);
            // Return early - the de-escalation already set the rates.
            return;
        }

        let level = self.intelligent_runtime_level() as u8;
        let current_padding = self.runtime_padding_rate.load(Ordering::Relaxed);
        let target_padding = match level {
            0 => 0u8,
            1 => self
                .env_snapshot
                .parse::<u8>("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1")
                .unwrap_or(50),
            _ => 100u8,
        };
        // Only update if different to avoid unnecessary atomic writes
        if current_padding != target_padding {
            self.escalate_to_level(level);
        }
    }

    fn server_push_burst_interval_secs(&self) -> u64 {
        if self.config.server_push_burst_interval == 0 {
            if matches!(self.config.mode, StealthMode::Intelligent) {
                // Level 2 (anti-dpi pressure): burst every 15s for stronger cover.
                // Level 0/1: every 30s to keep overhead minimal.
                if self.intelligent_runtime_level() >= 2 {
                    15
                } else {
                    30
                }
            } else {
                15
            }
        } else {
            self.config.server_push_burst_interval
        }
    }

    fn desired_masque_preference_with_hint(&self, telemetry_hint: u64) -> bool {
        let hits = self.probe_hits.load(Ordering::Relaxed);
        let escalated = self.escalated.load(Ordering::Relaxed);
        telemetry_hint == 1 || hits >= 3 || escalated
    }

    fn desired_masque_preference(&self) -> bool {
        // Read this connection's own brain hint, not the process-global telemetry counter. The
        // global read let one connection's telemetry flip another connection's MASQUE preference.
        let hint = u64::from(self.intelligent_level_hints.prefer_masque());
        self.desired_masque_preference_with_hint(hint)
    }

    fn server_push_cover_active(&self) -> bool {
        let intelligent_level = self.intelligent_runtime_level();
        let escalated = self.escalated.load(Ordering::Relaxed);
        let runtime_enabled = self.server_push_runtime_enabled.load(Ordering::Relaxed) || escalated;
        let enabled = self.config.enable_server_push_cover || runtime_enabled;
        enabled && (!matches!(self.config.mode, StealthMode::Intelligent) || intelligent_level >= 1)
    }

    fn current_server_push_state(&self) -> Option<(std::time::Instant, f32)> {
        if !self.server_push_cover_active() {
            return None;
        }

        let state = self.server_push_state.lock().unwrap_or_else(|e| e.into_inner());
        Some((state.last_burst, state.current_intensity))
    }

    /// Returns the current server-push cover plan only when the burst is due.
    pub(crate) fn server_push_cover_plan(&self) -> Option<(String, f32)> {
        let (last_burst, current_intensity) = self.current_server_push_state()?;
        let interval = std::time::Duration::from_secs(self.server_push_burst_interval_secs());
        if self.clock.elapsed_since(last_burst) < interval {
            return None;
        }
        Some((self.config.server_push_base_path.clone(), current_intensity))
    }

    /// Returns a bounded WebTransport-looking cover session plan.
    ///
    /// WebTransport cover is an H3 application-shape overlay only. It never
    /// replaces the production Core/H3/MASQUE VPN carrier and is kept out of
    /// the clean Performance/Intelligent level-0 path.
    pub(crate) fn webtransport_cover_plan(&self) -> Option<(String, String)> {
        let active = matches!(self.config.mode, StealthMode::AntiDpi)
            || (self.is_intelligent_runtime() && self.intelligent_runtime_level() >= 2);
        if !active || !self.config.enable_http3_masquerading {
            return None;
        }

        let authority = self
            .domain_fronting
            .as_ref()
            .map(DomainFrontingManager::get_fronted_domain)
            .unwrap_or_else(|| "cdn.cloudflare.com".to_string());
        let base = self.config.server_push_base_path.trim_end_matches('/');
        Some((authority, format!("{base}/wt/session")))
    }

    /// Exposes server-push cover plan for test assertions.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn server_push_cover_plan_for_test(&self) -> Option<(String, f32)> {
        self.server_push_cover_plan()
    }

    fn server_push_trigger_reason(
        &self,
        loss_rate_permille: u32,
        intelligent_level: u32,
    ) -> ServerPushTriggerReason {
        if loss_rate_permille >= 50 {
            ServerPushTriggerReason::Loss
        } else if intelligent_level >= 1 {
            ServerPushTriggerReason::Gating
        } else {
            ServerPushTriggerReason::Time
        }
    }

    fn estimate_server_push_cover_bytes(
        &self,
        base_path: &str,
        promises_created: usize,
        intensity: f32,
    ) -> u64 {
        if promises_created == 0 {
            return 0;
        }
        let per_promise = 280u64
            .saturating_add(base_path.len() as u64)
            .saturating_add((intensity.clamp(0.0, 1.0) * 180.0) as u64);
        per_promise.saturating_mul(promises_created as u64)
    }

    /// Records a server-push cover burst and updates telemetry/state accordingly.
    pub(crate) fn observe_server_push_burst(
        &self,
        base_path: &str,
        promises_created: usize,
        intensity: f32,
        loss_rate_permille: u32,
        intelligent_level: u32,
    ) {
        let reason = self.server_push_trigger_reason(loss_rate_permille, intelligent_level);
        let total_bytes =
            self.estimate_server_push_cover_bytes(base_path, promises_created, intensity);
        self.update_server_push_state(promises_created, total_bytes, reason);
    }

    fn update_server_push_state(
        &self,
        promises_created: usize,
        total_bytes: u64,
        reason: ServerPushTriggerReason,
    ) {
        if let Ok(mut state) = self.server_push_state.lock() {
            state.record_burst(&self.clock, promises_created, total_bytes);

            // Dynamic intensity adjustment based on escalation
            if self.escalated.load(Ordering::Relaxed) {
                state.current_intensity = (state.current_intensity * 1.2).min(1.0);
            } else {
                state.current_intensity =
                    (state.current_intensity * 0.95).max(self.config.server_push_intensity);
            }

            debug!(
                "Server Push state updated: {} promises, {} bytes, intensity {:.2}",
                promises_created, total_bytes, state.current_intensity
            );
            crate::optimize::telemetry::SERVER_PUSH_BURSTS_TOTAL
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::SERVER_PUSH_TOTAL_COVER_BYTES
                .fetch_add(total_bytes, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::SERVER_PUSH_BURSTS_LAST_MINUTE
                .store(state.bursts_last_minute() as u64, std::sync::atomic::Ordering::Relaxed);
            let intensity_ppm = state.intensity_ppm();
            crate::optimize::telemetry::SERVER_PUSH_CURRENT_INTENSITY_PPM
                .store(intensity_ppm, std::sync::atomic::Ordering::Relaxed);
            match reason {
                ServerPushTriggerReason::Time => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_TIME_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                ServerPushTriggerReason::Loss => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_LOSS_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                ServerPushTriggerReason::Gating => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_GATING_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    /// Escalate to Anti-DPI level features (without changing enum mode).
    /// This is the Level 2 escalation - full padding + timing + rotation.
    #[allow(dead_code)]
    fn escalate_to_anti_dpi_features(&self) {
        self.escalate_to_level(2);
    }

    /// Escalate to a specific stealth level (0=Performance, 1=Stealth, 2=AntiDpi).
    /// Each level sets graduated intensity on padding/timing/rotation.
    pub(crate) fn escalate_to_level(&self, level: u8) {
        let padding_rate = match level {
            0 => 0u8,
            1 => self
                .env_snapshot
                .parse::<u8>("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1")
                .unwrap_or(50),
            _ => 100u8,
        };
        let timing_rate = match level {
            0 | 1 => 0u8,
            _ => 100u8,
        };
        let rotation_rate = 0u8;
        self.runtime_padding_rate.store(padding_rate, Ordering::Relaxed);
        self.runtime_timing_rate.store(timing_rate, Ordering::Relaxed);
        self.runtime_rotation_rate.store(rotation_rate, Ordering::Relaxed);

        if level >= 2 {
            // Level 2: full escalation with server push cover
            if let Ok(mut st) = self.server_push_state.lock() {
                if st.current_intensity < 0.8 {
                    st.current_intensity = 0.8;
                }
            }
            if let Some(ref sched) = self.cover_traffic {
                sched.set_interval_ms(2500);
            }
        }
        debug!(
            "Stealth escalated to level {}: padding={}%, timing={}%, rotation={}%",
            level, padding_rate, timing_rate, rotation_rate
        );
    }

    /// De-escalate to a lower stealth level (called after quiet period).
    pub(crate) fn de_escalate_to_level(&self, level: u8) {
        self.escalate_to_level(level);
        if level == 0 {
            // Full reset: clear escalated flag and timer
            self.escalated.store(false, Ordering::Relaxed);
            if let Ok(mut guard) = self.escalated_until.lock() {
                *guard = None;
            }
        }
        debug!("Stealth de-escalated to level {}", level);
    }

    /// Get current runtime padding rate (0-100).
    #[cfg(test)]
    pub(crate) fn runtime_padding_rate(&self) -> u8 {
        self.runtime_padding_rate.load(Ordering::Relaxed)
    }

    /// Get current runtime timing rate (0-100).
    #[cfg(test)]
    pub(crate) fn runtime_timing_rate(&self) -> u8 {
        self.runtime_timing_rate.load(Ordering::Relaxed)
    }

    /// Get current runtime rotation rate (0-100).
    #[cfg(test)]
    pub(crate) fn runtime_rotation_rate(&self) -> u8 {
        self.runtime_rotation_rate.load(Ordering::Relaxed)
    }

    /// Get the current escalation level from the EscalationState (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn escalation_level(&self) -> u8 {
        self.escalation_state.current_level()
    }

    /// Record a probe in the escalation state machine (test accessor).
    /// Returns the new level if escalation occurred, None if no change.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn record_probe_for_test(&self) -> Option<u8> {
        self.escalation_state.record_probe()
    }

    /// Check and perform de-escalation if quiet period elapsed (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn check_de_escalation_for_test(&self) -> Option<u8> {
        self.escalation_state.check_de_escalation()
    }

    /// Reset escalation state (test-only).
    #[cfg(test)]
    pub fn reset_escalation_state(&self) {
        self.escalation_state.reset();
    }

    /// Set the Brain-owned level for focused runtime tests.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_brain_level_for_test(&self, level: u8) {
        self.intelligent_level_hints.set_brain_level_for_test(level);
    }

    /// Get probe count in 60s window (test-only).
    #[cfg(test)]
    pub fn probe_count_60s(&self) -> u32 {
        self.escalation_state.probe_count_60s()
    }

    /// Indicates whether MASQUE should be preferred while escalated and available.
    pub(crate) fn masque_preferred_runtime(&self) -> bool {
        self.prefer_masque.load(Ordering::Relaxed)
    }

    /// Returns whether MASQUE is currently preferred (test-only accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_preferred(&self) -> bool {
        self.masque_preferred_runtime()
    }

    /// Explicitly set MASQUE preference for test coverage.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_masque_preferred(&self, on: bool) {
        self.prefer_masque.store(on, Ordering::Relaxed);
    }

    /// Returns true if MASQUE datagram handling should be active.
    pub(crate) fn masque_datagram_enabled(&self) -> bool {
        StealthConfig::masque_env_flag(&self.env_snapshot, "QUICFUSCATE_MASQUE_DATAGRAM")
    }

    /// Determine MASQUE proxy authority to use.
    /// Priority: QUICFUSCATE_MASQUE_PROXY env -> first fronting domain (":443").
    pub(crate) fn masque_proxy(&self) -> Option<String> {
        if let Some(v) = StealthConfig::masque_proxy_override(&self.env_snapshot) {
            return Some(v);
        }
        if !self.config.fronting_domains.is_empty() {
            let d = &self.config.fronting_domains[0];
            if !d.is_empty() {
                return Some(format!("{}:443", d));
            }
        }
        None
    }

    /// Intelligent-mode hook: prefer the production Core H3/MASQUE carrier
    /// when probe or escalation pressure justifies it.
    fn maybe_escalate_masque_intelligent(&self) {
        if !matches!(self.config.mode, StealthMode::Intelligent) {
            return;
        }
        let desired_preference = self.desired_masque_preference();
        let current_preference = self.prefer_masque.load(Ordering::Relaxed);
        if current_preference != desired_preference {
            self.prefer_masque.store(desired_preference, Ordering::Relaxed);
        }
    }

    /// Triggers Intelligent-mode MASQUE escalation logic for testing.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn maybe_escalate_masque_intelligent_for_test(&self) {
        self.maybe_escalate_masque_intelligent();
    }

    /// Syncs MASQUE preference using a telemetry hint value (test-only).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn sync_masque_preference_with_hint_for_test(&self, telemetry_hint: u64) {
        if !matches!(self.config.mode, StealthMode::Intelligent) {
            return;
        }
        let desired_preference = self.desired_masque_preference_with_hint(telemetry_hint);
        self.prefer_masque.store(desired_preference, Ordering::Relaxed);
    }

    /// Keep Intelligent mode runtime controls in one place.
    /// This includes preference updates for Core H3/MASQUE selection and the
    /// base server-push runtime activation policy for that level.
    pub(crate) fn sync_intelligent_runtime_controls(&self, intelligent_level: u32) {
        if !self.is_intelligent_runtime() {
            return;
        }
        if intelligent_level > 0 {
            crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.maybe_escalate_masque_intelligent();
        if intelligent_level == 0 {
            self.enable_server_push_runtime(false, None);
            return;
        }
        let mut intensity = if intelligent_level >= 2 { 0.9 } else { 0.65 };
        intensity = self.escalation_min_server_push_intensity(intensity);
        self.enable_server_push_runtime(true, Some(intensity));
    }

    /// Toggles server-push cover traffic at runtime (test-only).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn enable_server_push_runtime_for_test(&self, enabled: bool, intensity: Option<f32>) {
        self.enable_server_push_runtime(enabled, intensity);
    }

    /// Forwards an invalid/probe packet to the Reality Proxy.
    ///
    /// When reality-grade TLS mimikry is enabled (TODO-415) and the cover cache
    /// has fresh material, the probe is served the cached cover-site ServerHello
    /// directly - no upstream relay needed. Otherwise, falls back to the
    /// `RealityProxy` relay path.
    pub(crate) fn handle_fallback(&self, packet: &[u8], source: std::net::SocketAddr) {
        // Phase 1 (TODO-415): serve cached cover material directly to probes.
        if let Some(material) = self.cover_handshake_material() {
            log::debug!(
                "Serving cached cover handshake ({} bytes) to probe from {}",
                material.server_hello.len(),
                source
            );
            if let Some(proxy) = &self.reality_proxy {
                // Phase 3 (TODO-415): serve the full cached TLS flight (ServerHello +
                // encrypted flight) directly to probes. This is byte-identical to
                // what the real cover site would return - the probe sees a valid
                // TLS 1.3 handshake response but cannot complete the key exchange
                // (no private key), exactly matching the XTLS-Reality approach.
                // Synchronous try_send - no tokio::spawn needed per probe.
                let raw_flight = material.raw_flight.clone();
                proxy.send_cached_response(source, raw_flight);
            }
            return;
        }
        if let Some(proxy) = &self.reality_proxy {
            proxy.forward_probe(packet, source);
        }
    }

    /// Returns cached cover-site TLS handshake material if reality-grade mimikry
    /// is enabled and the cache has fresh material. Returns `None` if disabled,
    /// cache empty, or material stale - caller should fall back to synthetic TLS.
    pub(crate) fn cover_handshake_material(
        &self,
    ) -> Option<std::sync::Arc<crate::reality::CoverMaterial>> {
        self.cover_cache.as_ref()?.get()
    }

    /// Returns true if a cover PING should be sent now, and advances the internal timer.
    ///
    /// Cover PINGs are ack-eliciting QUIC PING frames injected post-handshake to maintain
    /// realistic keepalive traffic patterns matching idle browser/HTTP3 sessions.
    pub(crate) fn should_send_cover_ping(&self) -> bool {
        if !self.config.enable_cover_ping || self.config.cover_ping_interval_ms == 0 {
            return false;
        }
        let interval = std::time::Duration::from_millis(self.config.cover_ping_interval_ms);
        let mut guard = self.next_cover_ping.lock();
        let now = self.clock.now();
        if now >= *guard {
            *guard = now.checked_add(interval).unwrap_or(now);
            true
        } else {
            false
        }
    }

    /// Polls for upstream responses to route back to the scanner.
    pub(crate) fn poll_fallback(&self) -> Option<crate::reality::FallbackResponse> {
        if let Ok(mut rx) = self.fallback_rx.try_lock() {
            if let Ok(resp) = rx.try_recv() {
                return Some(resp);
            }
        }
        None
    }
}

/// Snapshot of brain-derived signals consumed by the Intelligent-mode policy derivation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IntelligentStealthInputs {
    /// Brain-derived escalation level hint: 0=clean-path, 1=stealth, 2=anti-dpi pressure.
    pub level_hint: u8,
    /// Recent ECN-CE ratio (0.0-1.0) indicating congestion.
    pub ce_ratio_recent: f64,
    /// Smoothed ACK inter-arrival time in microseconds.
    pub ack_us: f64,
    /// Jensen-Shannon divergence of packet-size histogram vs baseline.
    pub size_div: f64,
    /// Jensen-Shannon divergence of inter-arrival-time histogram vs baseline.
    pub iat_div: f64,
    /// Fraction of out-of-order packets (0.0-1.0).
    pub reorder_ratio: f64,
    /// Accumulated RTT spike weight from Kalman filter outliers.
    pub rtt_spike_weight: f64,
    /// Count of ToS/DSCP anomaly signals in the current window.
    pub signal_tos: u64,
    /// Count of unclassified anomaly signals in the current window.
    pub signal_other: u64,
    /// Maximum jitter budget in microseconds for timing obfuscation.
    pub jitter_max_us: u32,
    /// Low-mode padding ceiling in bytes.
    pub pad_max_low: usize,
    /// High-mode padding ceiling in bytes.
    pub pad_max_high: usize,
}
