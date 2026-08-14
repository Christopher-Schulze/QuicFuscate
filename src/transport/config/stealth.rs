use super::{Config, TrafficAnalysisDefense, TrafficAnalysisPolicy};
use qf_stealth::OsFingerprintProfile;

impl Config {
    /// Sets the target OS fingerprint profile for TCP/ICMP packet normalization
    /// on the TUN egress path (TODO-462).
    pub fn set_fingerprint_profile(&mut self, profile: OsFingerprintProfile) {
        self.fingerprint_profile = profile;
    }

    /// Returns the currently configured OS fingerprint profile.
    pub fn fingerprint_profile(&self) -> OsFingerprintProfile {
        self.fingerprint_profile
    }

    // --- Multipath support (TODO-449) ---

    /// Enables or disables multipath (WiFi+LTE bonding) for this connection.
    pub fn set_multipath_enabled(&mut self, enabled: bool) {
        self.multipath_enabled = enabled;
    }

    /// Sets the maximum number of concurrent paths (primary + secondaries)
    /// when multipath is enabled. Clamped to at least 1.
    pub fn set_max_paths(&mut self, max_paths: usize) {
        self.max_paths = max_paths.max(1);
    }

    /// Returns whether multipath bonding is enabled.
    pub fn multipath_enabled(&self) -> bool {
        self.multipath_enabled
    }

    /// Returns the maximum number of concurrent paths.
    pub fn max_paths(&self) -> usize {
        self.max_paths
    }

    // --- Stealth padding and traffic-analysis defense (TODO-455) ---

    /// Sets the maximum number of active connection IDs the peer may use.
    pub fn set_active_connection_id_limit(&mut self, v: u64) {
        self.active_connection_id_limit = v;
    }

    /// Sets the 16-byte stateless reset token for this connection.
    pub fn set_stateless_reset_token(&mut self, token: [u8; 16]) {
        self.stateless_reset_token = Some(token);
    }

    /// Sets the initial address validation token for the first Initial packet.
    pub fn set_initial_token(&mut self, token: Option<Vec<u8>>) {
        self.initial_token = token;
    }

    /// Configures stealth padding (strategy: 0=off, 1=random, 2=fixed, 3=adaptive, 4=browser-mimic, 5=packet-normalize).
    pub fn set_stealth_padding(&mut self, enabled: bool, strategy: u8, max_size: usize) {
        self.stealth_padding_enabled = enabled;
        self.stealth_padding_strategy = strategy;
        self.stealth_padding_max_size = max_size;
    }

    /// Sets the padding application rate (0-100%).
    pub fn set_stealth_padding_rate(&mut self, rate: u8) {
        self.stealth_padding_rate = rate.min(100);
    }

    /// Sets the PacketNormalize target size (strategy 5). 0 = disabled.
    pub fn set_stealth_normalize_target(&mut self, target_size: usize) {
        self.stealth_normalize_target_size = target_size;
    }

    /// Configures stealth timing jitter injection.
    pub fn set_stealth_timing(&mut self, enabled: bool, max_jitter_us: u32) {
        self.stealth_timing_enabled = enabled;
        self.stealth_timing_max_jitter_us = max_jitter_us;
    }

    /// Sets the timing obfuscation rate (0-100%).
    pub fn set_stealth_timing_rate(&mut self, rate: u8) {
        self.stealth_timing_rate = rate.min(100);
    }

    /// Sets the adaptive padding granularity in bytes (minimum 1).
    pub fn set_stealth_adaptive_granularity(&mut self, gran: u16) {
        self.stealth_adaptive_granularity = if gran == 0 { 1 } else { gran };
    }

    /// Sets the browser mimic bias code (1=Safari, 2=Firefox, 3=Chromium, 4=Android).
    pub fn set_stealth_mimic_bias(&mut self, bias: u8) {
        self.stealth_mimic_bias = match bias {
            1..=4 => bias,
            _ => 3,
        };
    }

    /// Sets ACK-eliciting threshold (packets) before emitting ACK.
    pub fn set_ack_eliciting_threshold(&mut self, thr: u64) {
        self.ack_eliciting_threshold = thr.max(1);
    }

    /// Disables internal stealth timing sleeps when true.
    pub fn set_external_pacing(&mut self, v: bool) {
        self.external_pacing = v;
    }

    /// Sets the traffic analysis defense mode.
    pub fn set_traffic_analysis_defense(&mut self, mode: TrafficAnalysisDefense) {
        self.traffic_analysis_defense = mode;
        if matches!(mode, TrafficAnalysisDefense::ConstantRate)
            && self.constant_rate_pps > 0
            && self.chaff_rate_pps == 0
        {
            self.chaff_rate_pps = self.constant_rate_pps;
        }
    }

    /// Sets the traffic analysis defense mode from a string identifier.
    pub fn set_traffic_analysis_defense_str(
        &mut self,
        s: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        match TrafficAnalysisDefense::parse(s) {
            Some(mode) => {
                self.set_traffic_analysis_defense(mode);
                Ok(())
            }
            None => Err(crate::error::ConnectionError::InvalidState),
        }
    }

    /// Sets the chaff injection rate in packets per second.
    pub fn set_chaff_rate_pps(&mut self, pps: u32) {
        self.chaff_rate_pps = pps.min(10_000);
    }

    /// Sets the target chaff packet size in bytes. Clamped to [64, 65535].
    pub fn set_chaff_size_bytes(&mut self, size: u32) {
        self.chaff_size_bytes = size.clamp(64, 65_535);
    }

    /// Sets the constant-rate target emission rate in packets per second.
    pub fn set_constant_rate_pps(&mut self, pps: u32) {
        self.constant_rate_pps = pps.min(1_000);
    }

    /// Sets the full-rate idle window, bounded to one hour.
    pub fn set_chaff_idle_timeout_ms(&mut self, timeout_ms: u64) {
        self.chaff_idle_timeout_ms = timeout_ms.min(3_600_000);
    }

    /// Sets the soft-stop ramp duration, bounded to one minute.
    pub fn set_chaff_ramp_down_ms(&mut self, ramp_down_ms: u64) {
        self.chaff_ramp_down_ms = ramp_down_ms.min(60_000);
    }

    /// Atomically applies one validated traffic-analysis policy.
    pub fn set_traffic_analysis_policy(
        &mut self,
        policy: TrafficAnalysisPolicy,
    ) -> Result<(), &'static str> {
        let policy = policy.validate()?;
        self.traffic_analysis_defense = policy.defense;
        self.chaff_rate_pps = policy.chaff_rate_pps;
        self.chaff_size_bytes = policy.chaff_size_bytes;
        self.constant_rate_pps = policy.constant_rate_pps;
        self.chaff_idle_timeout_ms = policy.idle_timeout_ms;
        self.chaff_ramp_down_ms = policy.ramp_down_ms;
        Ok(())
    }

    /// Sets the independent ceiling for authenticated per-QKey policy requests.
    pub fn set_qkey_traffic_analysis_ceiling(
        &mut self,
        policy: TrafficAnalysisPolicy,
    ) -> Result<(), &'static str> {
        self.qkey_traffic_analysis_ceiling = policy.validate()?;
        Ok(())
    }

    /// Sets the operator ceiling for post-authentication Intelligent escalation.
    pub fn set_intelligent_traffic_analysis_ceiling(
        &mut self,
        policy: TrafficAnalysisPolicy,
    ) -> Result<(), &'static str> {
        self.intelligent_traffic_analysis_ceiling = policy.validate()?;
        Ok(())
    }

    /// Returns the active traffic analysis defense mode.
    pub fn traffic_analysis_defense(&self) -> TrafficAnalysisDefense {
        self.traffic_analysis_defense
    }

    /// Returns the configured chaff rate in packets per second.
    pub fn chaff_rate_pps(&self) -> u32 {
        self.chaff_rate_pps
    }

    /// Returns the configured chaff packet size in bytes.
    pub fn chaff_size_bytes(&self) -> u32 {
        self.chaff_size_bytes
    }

    /// Returns the configured constant-rate target in packets per second.
    pub fn constant_rate_pps(&self) -> u32 {
        self.constant_rate_pps
    }

    /// Returns the full-rate idle window in milliseconds.
    pub fn chaff_idle_timeout_ms(&self) -> u64 {
        self.chaff_idle_timeout_ms
    }

    /// Returns the soft-stop ramp duration in milliseconds.
    pub fn chaff_ramp_down_ms(&self) -> u64 {
        self.chaff_ramp_down_ms
    }

    /// Returns the complete effective traffic-analysis policy.
    pub fn traffic_analysis_policy(&self) -> TrafficAnalysisPolicy {
        TrafficAnalysisPolicy {
            defense: self.traffic_analysis_defense,
            chaff_rate_pps: self.chaff_rate_pps,
            chaff_size_bytes: self.chaff_size_bytes,
            constant_rate_pps: self.constant_rate_pps,
            idle_timeout_ms: self.chaff_idle_timeout_ms,
            ramp_down_ms: self.chaff_ramp_down_ms,
        }
    }

    /// Returns the authenticated per-QKey traffic-analysis policy ceiling.
    pub fn qkey_traffic_analysis_ceiling(&self) -> TrafficAnalysisPolicy {
        self.qkey_traffic_analysis_ceiling
    }

    /// Returns the post-authentication Intelligent escalation ceiling.
    pub fn intelligent_traffic_analysis_ceiling(&self) -> TrafficAnalysisPolicy {
        self.intelligent_traffic_analysis_ceiling
    }
}
