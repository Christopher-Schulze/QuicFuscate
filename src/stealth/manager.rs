use super::http3_masquerade::{FakeHeaders, FakeHeadersConfig};
use super::*;

/// The main stealth manager that coordinates all obfuscation techniques.
pub struct StealthManager {
    config: StealthConfig,
    /// Monotonic clock shared by every protocol-facing stealth child.
    clock: crate::time_source::ProtocolClock,
    /// Immutable environment generation used by this runtime owner.
    env_snapshot: Arc<crate::env_utils::EnvSnapshot>,
    fingerprint: Arc<Mutex<FingerprintProfile>>,
    /// Rotator over configured Reality cover targets (TODO-1048). Targets are
    /// hosts whose certificate the hop legitimately presents or relays.
    cover_targets: Option<CoverTargetRotator>,
    /// Cryptographic manager for key derivation.
    _crypto_manager: Arc<CryptoManager>,
    /// Whether this connection migrates its UDP port for disguise (TODO-1056).
    /// Enabled for `stealth`, `stealth_max`, and `dynamic`; off for `off` and
    /// `performance` — speed profiles never move the path for camouflage.
    disguise_migration_enabled: bool,
    /// Next scheduled disguise migration instant (clock domain). Redrawn from
    /// a uniform 120..=600 s window after every migration or real path change.
    next_disguise_migration: Mutex<std::time::Instant>,
    /// Active probe detector
    probe_detector: Option<ActiveProbeDetector>,
    /// Flow shaper for jitter and dummy retransmits
    flow_shaper: Option<FlowShaper>,
    /// Cover traffic scheduler
    cover_traffic: Option<CoverTrafficScheduler>,
    /// Whether the one-shot WebTransport cover session plan was claimed.
    webtransport_cover_claimed: AtomicBool,
    /// Escalation flag after probe detection
    escalated: AtomicBool,
    /// Escalation timeout
    escalated_until: Arc<Mutex<Option<std::time::Instant>>>,
    /// Prefer MASQUE path while escalated (when available)
    prefer_masque: AtomicBool,
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
}

#[cfg(test)]
#[path = "manager/coverage_tests.rs"]
mod coverage_tests;

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
        Self::new_internal(config, optimization_manager, crypto_manager, runtime_owner, clock)
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

        let cover_targets = Self::cover_targets_for_config(&config);

        let disguise_migration_enabled = matches!(
            config.mode,
            StealthMode::Stealth | StealthMode::StealthMax | StealthMode::Dynamic
        );
        let next_disguise_migration =
            Mutex::new(clock.now() + Self::draw_disguise_migration_delay());

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
            let jitter_us = if matches!(config.mode, StealthMode::StealthMax) { 3000 } else { 750 };
            Some(FlowShaper::new_with_clock(
                jitter_us,
                matches!(config.mode, StealthMode::StealthMax),
                &clock,
            ))
        } else {
            None
        };

        // Initialize cover traffic scheduler only for modes that intentionally
        // emit H3 cover requests. Performance keeps H3/QPACK persona active
        // but must not generate extra cover traffic on the clean path.
        let cover_traffic = if Self::cover_traffic_scheduler_allowed(&config) {
            // Cover traffic names a configured cover target, never a fronted
            // alias: the authority must match what the hop actually serves.
            let target = cover_targets
                .as_ref()
                .map_or_else(|| "cdn.cloudflare.com".to_string(), |ct| ct.next_cover_target());
            Some(CoverTrafficScheduler::new_with_clock(target, 5000, &clock)) // 5 second interval
        } else {
            None
        };

        // REALITY PROXY INITIALIZATION (TODO-1048): the probe fallback relays
        // to cover targets whenever Dynamic mode or explicit cover targets are
        // configured. StealthMax presets populate the target list; other modes
        // opt in by setting stealth.reality_cover_targets.
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let reality_proxy = if config.dynamic_enabled || !config.reality_cover_targets.is_empty() {
            Some(Arc::new(crate::reality::RealityProxy::new_with_targets(
                tx,
                &env_snapshot,
                &config.reality_cover_targets,
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
            cover_targets,
            _crypto_manager: crypto_manager,
            disguise_migration_enabled,
            next_disguise_migration,
            probe_detector,
            flow_shaper,
            cover_traffic,
            webtransport_cover_claimed: AtomicBool::new(false),
            escalated: AtomicBool::new(false),
            escalated_until: Arc::new(Mutex::new(None)),
            prefer_masque: AtomicBool::new(false),
            probe_hits: Arc::new(AtomicUsize::new(0)),
            escalation_state: Arc::new(EscalationState::new(
                Arc::clone(&intelligent_level_hints),
                &env_snapshot,
            )),
            intelligent_level_hints,
            runtime_padding_rate: AtomicU8::new(0),
            runtime_timing_rate: AtomicU8::new(0),
            _optimization_manager: optimization_manager,
            reality_proxy,
            fallback_rx: Arc::new(Mutex::new(rx)),
            cover_cache,
            _background_owner: runtime_owner,
        }
    }

    /// Build the cover-target rotator from configuration. An explicit
    /// `reality_cover_targets` list (including the StealthMax preset's broad
    /// provider set) yields a rotator; an empty list means no cover targets.
    fn cover_targets_for_config(config: &StealthConfig) -> Option<CoverTargetRotator> {
        if config.reality_cover_targets.is_empty() {
            return None;
        }
        Some(CoverTargetRotator::new(config.reality_cover_targets.clone()))
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

    /// Draws the next disguise-migration delay: a uniform 120..=600 s window
    /// (TODO-1056). A new draw happens per connection and after every
    /// migration — never a fixed cadence a classifier could lock onto.
    fn draw_disguise_migration_delay() -> std::time::Duration {
        let jitter_secs = crate::transport::rand::fast_rand_u64_uniform(481);
        std::time::Duration::from_secs(120 + jitter_secs)
    }

    /// Whether the disguise migration timer has fired (TODO-1056).
    ///
    /// The caller performs the actual migration through the path API. Speed
    /// profiles (`off`, `performance`) never report due — they do not move the
    /// path for camouflage.
    pub(crate) fn disguise_migration_due(&self) -> bool {
        if !self.disguise_migration_enabled {
            return false;
        }
        let next = self.next_disguise_migration.lock().unwrap_or_else(|p| p.into_inner());
        self.clock.now() >= *next
    }

    /// Records that a disguise migration (or a real path change) happened and
    /// draws the next migration instant (TODO-1056). Called on success and on
    /// failure alike — a failed migration must not trigger a retry storm.
    pub(crate) fn note_disguise_migration(&self) {
        let next = self.clock.now() + Self::draw_disguise_migration_delay();
        *self.next_disguise_migration.lock().unwrap_or_else(|p| p.into_inner()) = next;
    }

    /// Builds the shared wire byte ledger for a new connection (TODO-1052).
    ///
    /// One account for repairs, padding, and cover traffic. `off` and
    /// `performance` profiles carry a zero cap and yield `None` — no ledger
    /// is installed and the connection adds zero stealth bytes. `manual`
    /// keeps the operator-selected shape; every other stealth mode replays
    /// the active persona's captured length classes.
    ///
    /// `dynamic` installs the ledger at connect even though padding starts
    /// disabled: when the escalation engine later turns padding on through
    /// the brain runtime delta, the stealth bytes flow through the shape
    /// the connection committed to (TODO-1052/1059). The transport-side
    /// `stealth_padding_enabled` flag stays false until then, so an
    /// unescalated dynamic connection still emits zero stealth bytes.
    pub(crate) fn build_wire_ledger(&self, now: std::time::Instant) -> Option<BudgetLedger> {
        let dynamic = matches!(self.config.mode, StealthMode::Dynamic);
        if !dynamic && !self.config.enable_traffic_padding {
            return None;
        }
        // Every connection that can emit stealth bytes owns a ledger —
        // `dynamic` because the brain may escalate later, every padded
        // mode because the ledger is the only padding authority. A zero
        // cap means "operator never configured one": inherit the stealth
        // default. An operator who truly wants zero uses `off`, which
        // never installs a ledger at all.
        let (cap_sec, cap_burst) = if self.config.wire_cap_bytes_per_sec == 0 {
            let d = WireBudget::stealth_default();
            (d.cap_bytes_per_sec, d.cap_bytes_per_burst)
        } else {
            (self.config.wire_cap_bytes_per_sec, self.config.wire_cap_bytes_per_burst)
        };
        let budget = WireBudget {
            cap_bytes_per_sec: cap_sec,
            cap_bytes_per_burst: cap_burst,
            shape: self.config.wire_shape,
        };
        let trace = match self.config.wire_shape {
            WireShape::PersonaTrace => Some(qf_stealth::wire_budget::persona_trace(
                qf_stealth::transport_params::EngineFamily::from_browser(
                    self.current_fingerprint().browser,
                ),
            )),
            WireShape::FixedCell => None,
        };
        Some(BudgetLedger::new(budget, trace, self.config.normalize_target_size, now))
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
    pub(crate) fn runtime_tls_profile(&self, sni_override: Option<&str>) -> qf_stealth::TlsProfile {
        let fingerprint = self.current_fingerprint();
        let mut profile = qf_stealth::profile_from_fingerprint(&fingerprint);
        if let Some(sni) = sni_override {
            profile.sni = Some(sni.to_string());
        }
        profile.cover_performance_mode = matches!(
            self.config.mode,
            StealthMode::Off | StealthMode::Performance | StealthMode::Dynamic
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

        // Apply the QUIC transport parameters from the persona's capture
        // fixture. FingerprintProfile::new_with_snapshot populates every
        // field below from the same fixture table that drives the Initial
        // transport-parameter block, so internal config and advertised
        // parameters cannot drift (TODO-1047).
        config.set_initial_max_data(fingerprint.initial_max_data);
        config
            .set_initial_max_stream_data_bidi_local(fingerprint.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(
            fingerprint.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_stream_data_uni(fingerprint.initial_max_stream_data_uni);
        config.set_initial_max_streams_bidi(fingerprint.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(fingerprint.initial_max_streams_uni);
        config.set_max_idle_timeout(fingerprint.max_idle_timeout);

        if self.config.enable_realtime_choke && self.config.choke_target_mbps > 0 {
            let bytes_per_sec = u64::from(self.config.choke_target_mbps).saturating_mul(125_000);
            if bytes_per_sec > 0 {
                config.set_max_pacing_rate(bytes_per_sec);
            }
        }

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
        drop(fingerprint);
        self.apply_stealth_transport_knobs(config);
    }

    /// Applies padding, timing, and pacing knobs even when uTLS is off.
    /// `--no-utls` only skips the persona/ACK overlay; reorder and jitter
    /// still need these transport flags or the window never arms.
    pub(crate) fn apply_stealth_transport_knobs(&self, config: &mut crate::transport::Config) {
        if matches!(self.config.mode, StealthMode::StealthMax) {
            config.set_external_pacing(true);
        }

        // ENV overrides (advanced tuning)
        if let Some(n) = self.config.transport_ack_threshold_override(&self.env_snapshot) {
            config.set_ack_eliciting_threshold(n);
        }
        if let Some(ms) = self.config.transport_ack_max_delay_override(&self.env_snapshot) {
            config.set_max_ack_delay(ms);
        }
        if let Some(enabled) = self.config.transport_external_pacing_override(&self.env_snapshot) {
            config.set_external_pacing(enabled);
        }

        // Apply stealth padding knobs to transport config so Connection::send() can pad before sealing.
        // TODO-1052: the wire shape is the only strategy; 6 = persona trace,
        // 7 = fixed cell. The BudgetLedger (installed on the connection)
        // enforces the shared cap across repairs, padding, and cover.
        let strategy_code = match self.config.wire_shape {
            WireShape::PersonaTrace => 6,
            WireShape::FixedCell => 7,
        };
        config.set_stealth_padding(
            self.config.enable_traffic_padding,
            strategy_code,
            self.config.max_padding_size,
        );
        // Set default adaptive granularity (bytes) - sensible default 64
        config.set_stealth_adaptive_granularity(64);
        let fingerprint = self.current_fingerprint();
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
        // - QUICFUSCATE_STEALTH_PADDING_STRATEGY = persona-trace|fixed-cell
        //   (legacy spellings random|adaptive|browser|fixed|normalize collapse)
        // - QUICFUSCATE_STEALTH_JITTER_US = <u32>
        if let Some(v) = self.config.transport_padding_max_override(&self.env_snapshot) {
            config.set_stealth_padding(self.config.enable_traffic_padding, strategy_code, v);
        }
        if let Some(shape) = self.config.transport_wire_shape_override(&self.env_snapshot) {
            let scode = match shape {
                WireShape::PersonaTrace => 6,
                WireShape::FixedCell => 7,
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
        if let Some(gran) = self.config.transport_adaptive_granularity_override(&self.env_snapshot)
        {
            config.set_stealth_adaptive_granularity(gran);
        }
        if let Some(code) = self.config.transport_mimic_bias_override(&self.env_snapshot) {
            config.set_stealth_mimic_bias(code);
        } else {
            config.set_stealth_mimic_bias(bias_default);
        }
    }

    /// Processes an outgoing packet payload, applying configured stealth techniques.
    /// Returns an optional delay Duration if the packet should be delayed (Async Scheduler).
    /// Does NOT block the thread.
    ///
    /// `ack_only` marks datagrams carrying no ack-eliciting frames (pure ACK /
    /// PADDING / CONNECTION_CLOSE). They are never delayed. A manual bandwidth
    /// cap, when enabled, replaces the congestion controller pacing rate and
    /// does not add a second sleep.
    pub(crate) fn process_outgoing_packet(
        &self,
        _payload: &mut [u8],
        ack_only: bool,
    ) -> Option<std::time::Duration> {
        // Shaping delays are merged in core::QuicFuscateConnection::send() with transport
        // jitter (when active). One release gate: the shared deferral window.
        // Stealth MAX jitter applies only to ack-eliciting packets and is
        // clamped to PTO/4 at the send clock. A manual bandwidth cap, if set,
        // replaces the pacer rate instead of sleeping here.
        let mut total_delay = std::time::Duration::ZERO;
        let anti_mode = matches!(self.config.mode, StealthMode::StealthMax);

        // The congestion controller is the only continuous limiter. A manual
        // bandwidth cap replaces the pacer rate in `apply_utls_profile`.
        // RateChoker::shape does not add a second delay on top of that.
        if !ack_only && !self.config.enable_realtime_choke && anti_mode {
            if let Some(flow_shaper) = &self.flow_shaper {
                total_delay = flow_shaper.apply_jitter() + flow_shaper.apply_flight_pacing(false);
            }
        }

        // Telemetry for calculated delay (Async Mode)
        if !total_delay.is_zero() {
            let ms = total_delay.as_millis() as u64;
            crate::telemetry::CHOKE_SLEEP_MS.inc_by(ms);
        }

        // Record packet into history to consume PacketInfo fields. ACK-only
        // datagrams still occupy the wire, so they feed the rate estimator -
        // they just are not delay targets.
        if anti_mode {
            if let Some(shaper) = &self.flow_shaper {
                let ty = if ack_only { StealthPacketClass::Ack } else { StealthPacketClass::Data };
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
    /// - Level 0 -> 1: >=3 probes within 60 seconds.
    /// - Level 1 -> 2: >=8 probes within 120 seconds.
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
                    *guard =
                        self.clock.checked_deadline_after(std::time::Duration::from_secs(20 * 60));
                }

                // Keep the active Browser/OS/TLS/H3 persona stable. Escalation
                // may raise padding, timing, cover traffic and MASQUE hints,
                // but it must not rotate fingerprints or fronting hosts inside
                // an already-established connection.
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

    /// Returns the next outer-hop cover request `(authority, path)` once the
    /// weighted scheduler interval elapsed, otherwise `None`. The caller
    /// encodes the headers through [`Self::get_http3_header_list`] — one
    /// persona code path — and debits the wire ledger (TODO-1055).
    pub(crate) fn cover_request_due(&self) -> Option<(String, String)> {
        if !self.cover_header_emission_allowed() {
            return None;
        }
        self.cover_traffic.as_ref().and_then(|sched| sched.next_cover_target())
    }

    fn cover_traffic_scheduler_allowed(config: &StealthConfig) -> bool {
        config.enable_http3_masquerading
            && !matches!(config.mode, StealthMode::Off | StealthMode::Performance)
    }

    fn cover_header_emission_allowed(&self) -> bool {
        match self.config.mode {
            StealthMode::Off | StealthMode::Performance => false,
            StealthMode::Dynamic => self.intelligent_runtime_level() >= 1,
            StealthMode::Stealth | StealthMode::StealthMax | StealthMode::Manual => true,
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
        matches!(self.config.mode, StealthMode::Dynamic)
    }

    pub(crate) fn environment_snapshot(&self) -> Arc<crate::env_utils::EnvSnapshot> {
        Arc::clone(&self.env_snapshot)
    }

    /// Computes which transport knobs the brain is allowed to adjust at runtime.
    pub(crate) fn brain_runtime_permissions(&self) -> crate::transport::BrainRuntimePermissions {
        let ack_locked = self.config.transport_ack_threshold_override(&self.env_snapshot).is_some()
            || self.config.transport_ack_max_delay_override(&self.env_snapshot).is_some();
        let timing_locked =
            self.config.transport_external_pacing_override(&self.env_snapshot).is_some()
                || self.config.transport_jitter_override_us(&self.env_snapshot).is_some();
        let padding_locked = self
            .config
            .transport_padding_max_override(&self.env_snapshot)
            .is_some()
            || self.config.transport_wire_shape_override(&self.env_snapshot).is_some()
            || self.config.transport_adaptive_granularity_override(&self.env_snapshot).is_some()
            || self.config.transport_mimic_bias_override(&self.env_snapshot).is_some();
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
    #[cfg(test)]
    pub(crate) fn derive_intelligent_runtime_policy(
        inputs: IntelligentStealthInputs,
    ) -> crate::transport::StealthRuntimePolicy {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::derive_intelligent_runtime_policy_with_snapshot(inputs, &environment)
    }

    #[cfg(test)]
    pub(crate) fn derive_intelligent_runtime_policy_with_snapshot(
        inputs: IntelligentStealthInputs,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> crate::transport::StealthRuntimePolicy {
        qf_stealth::derive_intelligent_runtime_policy(inputs, environment)
    }

    /// Returns true if active stealth features (beyond Performance/Off) are engaged.
    #[cfg(feature = "orchestrator")]
    pub(crate) fn runtime_stealth_active(&self) -> bool {
        !matches!(self.config.mode, StealthMode::Performance | StealthMode::Off)
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

    /// Returns a bounded WebTransport-looking cover session plan.
    ///
    /// WebTransport cover is an H3 application-shape overlay only. It never
    /// replaces the production Core/H3/MASQUE VPN carrier and is kept out of
    /// the clean Performance/Intelligent level-0 path. The plan is claimed on
    /// first read — at most one session is opened per connection.
    pub(crate) fn webtransport_cover_plan(&self) -> Option<(String, String)> {
        if !self.webtransport_cover_enabled() {
            return None;
        }
        if self.webtransport_cover_claimed.swap(true, Ordering::Relaxed) {
            return None;
        }

        let authority = self
            .cover_targets
            .as_ref()
            .map_or_else(|| "cdn.cloudflare.com".to_string(), |ct| ct.next_cover_target());
        Some((authority, "/wt/session".to_string()))
    }

    /// Returns whether HTTP/3 requests may use the persona QPACK dynamic
    /// table and header-name index policy (outer-hop requests only).
    pub(crate) fn use_qpack_headers(&self) -> bool {
        self.config.use_qpack_headers
    }

    /// Returns whether this connection persona may negotiate WebTransport cover.
    pub(crate) fn webtransport_cover_enabled(&self) -> bool {
        let active = matches!(self.config.mode, StealthMode::StealthMax)
            || (self.is_intelligent_runtime() && self.intelligent_runtime_level() >= 2);
        active && self.config.enable_http3_masquerading
    }

    /// Escalate to a specific stealth level (0=performance, 1=stealth, 2=Stealth MAX).
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
        self.runtime_padding_rate.store(padding_rate, Ordering::Relaxed);
        self.runtime_timing_rate.store(timing_rate, Ordering::Relaxed);

        if level >= 2 {
            // Level 2: full escalation tightens the cover-request cadence.
            if let Some(ref sched) = self.cover_traffic {
                sched.set_interval_ms(2500);
            }
        }
        debug!(
            "Stealth escalated to level {}: padding={}%, timing={}%",
            level, padding_rate, timing_rate
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
    /// Priority: QUICFUSCATE_MASQUE_PROXY env -> first cover target (":443").
    pub(crate) fn masque_proxy(&self) -> Option<String> {
        if let Some(v) = StealthConfig::masque_proxy_override(&self.env_snapshot) {
            return Some(v);
        }
        if let Some(target) =
            self.config.reality_cover_targets.first().map(|d| d.trim()).filter(|d| !d.is_empty())
        {
            return Some(if target.contains(':') {
                target.to_string()
            } else {
                format!("{target}:443")
            });
        }
        None
    }

    /// Intelligent-mode hook: prefer the production Core H3/MASQUE carrier
    /// when probe or escalation pressure justifies it.
    fn maybe_escalate_masque_intelligent(&self) {
        if !matches!(self.config.mode, StealthMode::Dynamic) {
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
        if !matches!(self.config.mode, StealthMode::Dynamic) {
            return;
        }
        let desired_preference = self.desired_masque_preference_with_hint(telemetry_hint);
        self.prefer_masque.store(desired_preference, Ordering::Relaxed);
    }

    /// Keep Intelligent mode runtime controls in one place.
    /// This includes preference updates for Core H3/MASQUE selection.
    pub(crate) fn sync_intelligent_runtime_controls(&self, intelligent_level: u32) {
        if !self.is_intelligent_runtime() {
            return;
        }
        if intelligent_level > 0 {
            crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.maybe_escalate_masque_intelligent();
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

    /// Whether this connection may emit cover PINGs at all (TODO-1054).
    /// This is only a policy gate: the fixed interval grid is gone — the
    /// persona trace inside the wire ledger decides *when* a PING is due
    /// and how long its datagram is. `off`/`performance` and FixedCell
    /// (no trace) never emit.
    pub(crate) fn cover_ping_enabled(&self) -> bool {
        self.config.enable_cover_ping
            && !matches!(self.config.mode, StealthMode::Off | StealthMode::Performance)
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
