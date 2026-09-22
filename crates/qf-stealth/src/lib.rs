//! Root-independent stealth helpers shared by the product stealth manager.
//!
//! The root package keeps compatibility projections for the historical private
//! types while this crate owns cover-target rotation and flow-shaping state.

#[doc(hidden)]
pub use config::{RotationMode, StealthMode};
#[doc(hidden)]
pub use cover_targets::{CdnProvider, CoverTargetRotator};
#[doc(hidden)]
pub use cover_traffic::CoverTrafficScheduler;
#[doc(hidden)]
pub use escalation::EscalationState;
#[doc(hidden)]
pub use fingerprint::{
    update_ip_checksum_incremental, update_tcp_checksum_incremental, IcmpUnreachablePolicy,
    IpIdBehavior, NormalizeOutcome, NormalizeResult, OsFingerprintProfile, PacketNormalizer,
};
#[doc(hidden)]
pub use fingerprint_profile::{
    parse_fingerprint_profile_slot, FingerprintProfile, TlsCoverCipherPreference,
};
#[doc(hidden)]
pub use flow_shaping::{FlowShaper, StealthPacketClass};
#[doc(hidden)]
pub use http3_masquerade::Http3Masquerade;
#[doc(hidden)]
pub use intelligent_policy::{derive_intelligent_runtime_policy, IntelligentStealthInputs};
#[doc(hidden)]
pub use profiles::{parse_profile_slot, BrowserProfile, OsProfile};
#[doc(hidden)]
pub use rotation::FingerprintRotationConfig;
#[doc(hidden)]
pub use stealth_config::{FecMode, StealthConfig};
#[doc(hidden)]
pub use tls_client_hello::TlsClientHelloProfileCatalog;
#[doc(hidden)]
pub use tls_cover::{
    derive_tls_cover_material, derive_tls_cover_material_from_entropy, plan_tls_cover_record,
    TlsCoverCipherSuite, TlsCoverRecordPlan, TlsCoverRecordPlanError,
};
#[doc(hidden)]
pub use tls_profile::{profile_from_fingerprint, TlsProfile};
#[doc(hidden)]
pub use traffic::RateChoker;
pub use wire_budget::{BudgetLedger, PersonaTrace, WireBudget, WireShape};

#[doc(hidden)]
pub use chaff::{
    ChaffGenerator, TrafficAnalysisPhase, TrafficAnalysisScheduler, CHAFF_PADDING_FRAME_BYTE,
};
#[doc(hidden)]
pub use probe_detector::{ActiveProbeDetector, ProbeResponseMode};

#[doc(hidden)]
pub mod chaff;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod cover_traffic;
#[doc(hidden)]
pub mod escalation;
#[doc(hidden)]
pub mod fingerprint;
#[doc(hidden)]
pub mod fingerprint_profile;
#[doc(hidden)]
pub mod http3_masquerade;
#[doc(hidden)]
pub mod intelligent_policy;
#[doc(hidden)]
pub mod probe_detector;
#[doc(hidden)]
pub mod profiles;
#[doc(hidden)]
pub mod rotation;
#[doc(hidden)]
pub mod stealth_config;
#[doc(hidden)]
mod tls_client_hello;
#[doc(hidden)]
pub mod tls_cover;
#[doc(hidden)]
pub mod tls_profile;
#[doc(hidden)]
pub mod traffic;

pub mod transport_params;

pub mod wire_budget;

mod cover_targets {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const DEFAULT_COVER_TARGET: &str = "cdn.cloudflare.com";

    /// Supported CDN providers for cover-target rotation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[doc(hidden)]
    pub enum CdnProvider {
        Cloudflare,
        Fastly,
        Akamai,
        CloudFront,
        GoogleCloud,
        AzureCDN,
        StackPath,
        KeyCDN,
        BunnyCDN,
        Imperva,
    }

    impl CdnProvider {
        fn domains(self) -> Vec<&'static str> {
            match self {
                Self::Cloudflare => vec![
                    "cdn.cloudflare.com",
                    "cloudflare-dns.com",
                    "one.one.one.one",
                    "warp.plus",
                    "workers.dev",
                ],
                Self::Fastly => vec!["cdn.fastly.net", "fastly.com", "fastlylb.net", "fsly.net"],
                Self::Akamai => vec![
                    "akamaized.net",
                    "akamai.net",
                    "akamaihd.net",
                    "akamaitechnologies.com",
                    "edgesuite.net",
                ],
                Self::CloudFront => {
                    vec!["cloudfront.net", "amazonaws.com", "aws.amazon.com", "awsstatic.com"]
                }
                Self::GoogleCloud => vec![
                    "googleapis.com",
                    "googleusercontent.com",
                    "googlevideo.com",
                    "gstatic.com",
                    "google.com",
                ],
                Self::AzureCDN => {
                    vec!["azureedge.net", "azure.microsoft.com", "windows.net", "msecnd.net"]
                }
                Self::StackPath => vec!["stackpathdns.com", "stackpathcdn.com", "bootstrapcdn.com"],
                Self::KeyCDN => vec!["kxcdn.com", "keycdn.com"],
                Self::BunnyCDN => vec!["b-cdn.net", "bunnycdn.com"],
                Self::Imperva => vec!["incapdns.net", "imperva.com"],
            }
        }
    }

    /// Thread-safe rotation over cover-target hostnames.
    ///
    /// Cover targets are names whose certificate the selected hop legitimately
    /// presents or relays (TODO-1048): they name real endpoints, never an SNI
    /// that disagrees with the certificate of the connection it is sent on.
    #[doc(hidden)]
    pub struct CoverTargetRotator {
        targets: Arc<[String]>,
        index: AtomicUsize,
    }

    impl CoverTargetRotator {
        /// Create a rotator from an explicit cover-target list.
        #[inline]
        #[doc(hidden)]
        pub fn new(targets: Vec<String>) -> Self {
            Self { targets: Arc::from(targets), index: AtomicUsize::new(0) }
        }

        /// Create a rotator from all targets exposed by the given providers.
        #[inline]
        #[doc(hidden)]
        pub fn from_providers(providers: Vec<CdnProvider>) -> Self {
            let targets = providers
                .into_iter()
                .flat_map(|provider| provider.domains().into_iter().map(str::to_owned))
                .collect();
            Self::new(targets)
        }

        /// Create the built-in broad provider rotation.
        #[inline]
        #[doc(hidden)]
        pub fn broad_providers() -> Self {
            Self::from_providers(vec![
                CdnProvider::Cloudflare,
                CdnProvider::Fastly,
                CdnProvider::Akamai,
                CdnProvider::CloudFront,
                CdnProvider::GoogleCloud,
                CdnProvider::AzureCDN,
                CdnProvider::StackPath,
                CdnProvider::KeyCDN,
                CdnProvider::BunnyCDN,
                CdnProvider::Imperva,
            ])
        }

        /// Select the next configured cover target using strict round-robin order.
        #[inline]
        #[doc(hidden)]
        pub fn next_cover_target(&self) -> String {
            if self.targets.is_empty() {
                return DEFAULT_COVER_TARGET.to_owned();
            }
            let current = self.index.fetch_add(1, Ordering::Relaxed);
            self.targets[current % self.targets.len()].clone()
        }

        /// Return the configured cover targets for compatibility projections and tests.
        #[inline]
        #[doc(hidden)]
        pub fn targets(&self) -> &[String] {
            &self.targets
        }

        /// Select a random configured cover target, falling back to the default.
        #[inline]
        #[doc(hidden)]
        pub fn random_cover_target(&self) -> String {
            use rand::seq::IndexedRandom;
            let mut rng = rand::rng();
            self.targets
                .as_ref()
                .choose(&mut rng)
                .cloned()
                .unwrap_or_else(|| DEFAULT_COVER_TARGET.to_owned())
        }
    }
}

mod flow_shaping {
    use qf_common::time_source::ProtocolClock;
    use rand::Rng;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Stealth packet class tracked by the flow-shaping history.
    #[derive(Clone, Copy)]
    #[doc(hidden)]
    pub enum StealthPacketClass {
        Data,
        Ack,
        Retransmit,
        Dummy,
    }

    #[derive(Clone)]
    struct PacketInfo {
        timestamp: Instant,
        _size: usize,
        _packet_type: StealthPacketClass,
    }

    /// Jitter and handshake pacing helper used by the stealth manager.
    #[doc(hidden)]
    pub struct FlowShaper {
        clock: ProtocolClock,
        jitter_min_us: u64,
        jitter_max_us: u64,
        packet_history: Arc<Mutex<VecDeque<PacketInfo>>>,
        /// Mirror of `packet_history.len()` so the read-only jitter path does
        /// not contend on the history mutex - `record_and_prune` keeps it in
        /// sync while it already holds the lock.
        history_count: AtomicUsize,
        /// Anchor instant; `Instant` is not atomic, so the last-send gap is
        /// tracked as a microsecond offset from this anchor instead.
        anchor: Instant,
        /// Offset of the most recent recorded send in microseconds since
        /// `anchor`; `u64::MAX` until the first packet is recorded.
        last_send_offset_us: AtomicU64,
        _enabled: AtomicBool,
    }

    impl FlowShaper {
        /// Create a shaper using the process clock.
        #[doc(hidden)]
        pub fn new(jitter_us: u64, enable_dummy_retransmits: bool) -> Self {
            Self::new_with_clock(jitter_us, enable_dummy_retransmits, &ProtocolClock::default())
        }

        /// Create a shaper using an explicit clock for deterministic ownership.
        #[doc(hidden)]
        pub fn new_with_clock(
            jitter_us: u64,
            _enable_dummy_retransmits: bool,
            clock: &ProtocolClock,
        ) -> Self {
            let jitter_max_us = jitter_us.max(1);
            Self {
                clock: clock.clone(),
                jitter_min_us: (jitter_max_us / 2).max(1),
                jitter_max_us,
                packet_history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
                history_count: AtomicUsize::new(0),
                anchor: clock.now(),
                last_send_offset_us: AtomicU64::new(u64::MAX),
                _enabled: AtomicBool::new(true),
            }
        }

        /// Return a traffic-aware jitter delay.
        ///
        /// TODO-903: The previous distribution was flat uniform over
        /// `[max/2, max]` regardless of traffic state, which smooths bursts
        /// into an unnatural constant-ish profile a DPI stack can fingerprint.
        /// Real client flows alternate tight bursts and long gaps. This shaper
        /// derives the recent send rate from the already-recorded bounded
        /// history and shapes accordingly:
        /// - bursty (>= 32 packets in the 2s window): sample from the LOW half
        ///   of the range so bursts stay tight;
        /// - idle (< 8 packets): sample from the FULL range for wide spread;
        /// - steady: unchanged uniform over `[max/2, max]`.
        ///
        /// TODO-1010 (WF-A2D): position-aware perturbation. Website-
        /// fingerprinting classifiers extract most of their signal from burst
        /// *boundaries* (train start/end timing), not the burst interior.
        /// The first packet after an idle gap therefore always samples the
        /// FULL jitter range regardless of the traffic class, while interior
        /// burst packets stay tight - the perturbation budget lands where the
        /// fingerprint lives instead of being spread uniformly.
        #[doc(hidden)]
        pub fn apply_jitter(&self) -> Duration {
            let (min_us, max_us) = if self.is_burst_edge() {
                (1, self.jitter_max_us)
            } else {
                self.jitter_range_for_traffic()
            };
            let jitter_us = rand::rng().random_range(min_us..=max_us);
            Duration::from_micros(jitter_us)
        }

        /// Gap threshold in microseconds: an inter-send gap larger than this
        /// marks the next packet as the start of a new burst train.
        const BURST_EDGE_GAP_US: u64 = 100_000;

        /// True when the next send is a burst-train edge (first packet ever,
        /// or the first packet after a >=100 ms idle gap).
        fn is_burst_edge(&self) -> bool {
            let last = self.last_send_offset_us.load(Ordering::Relaxed);
            if last == u64::MAX {
                return true;
            }
            let now_offset_us =
                self.clock.elapsed_since(self.anchor).as_micros().min(u64::MAX as u128) as u64;
            now_offset_us.saturating_sub(last) >= Self::BURST_EDGE_GAP_US
        }

        /// Resolve the effective jitter range from recent traffic intensity.
        fn jitter_range_for_traffic(&self) -> (u64, u64) {
            let recent = self.history_count.load(Ordering::Relaxed);
            if recent >= 32 {
                // Burst: keep packets tight - low half of the range only,
                // floored so the minimum stays at least a quarter of max.
                let burst_min = (self.jitter_min_us / 2).max(1);
                let burst_max = (self.jitter_max_us / 2).max(burst_min);
                (burst_min, burst_max)
            } else if recent < 8 {
                // Idle: wide spread across the full range.
                (1, self.jitter_max_us)
            } else {
                // Steady: classic uniform [max/2, max].
                (self.jitter_min_us, self.jitter_max_us)
            }
        }

        /// Return conservative handshake-flight pacing.
        #[doc(hidden)]
        pub fn apply_flight_pacing(&self, is_handshake: bool) -> Duration {
            if is_handshake {
                Duration::from_millis(15)
            } else {
                Duration::ZERO
            }
        }

        /// Record one packet and retain only a bounded recent history.
        #[doc(hidden)]
        pub fn record_and_prune(&self, size: usize, packet_type: StealthPacketClass) {
            let now = self.clock.now();
            self.last_send_offset_us.store(
                self.clock.elapsed_since(self.anchor).as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            let Ok(mut history) = self.packet_history.lock() else {
                return;
            };
            history.push_back(PacketInfo {
                timestamp: now,
                _size: size,
                _packet_type: packet_type,
            });
            while let Some(front) = history.front() {
                if self.clock.elapsed_since(front.timestamp) > Duration::from_secs(2)
                    || history.len() > 256
                {
                    history.pop_front();
                } else {
                    break;
                }
            }
            // Keep the mirror exact so the lock-free jitter path sees the same
            // count the deque holds after push + prune.
            self.history_count.store(history.len(), Ordering::Relaxed);
        }

        /// Return the current bounded history length for diagnostics and tests.
        #[doc(hidden)]
        pub fn history_len(&self) -> usize {
            self.history_count.load(Ordering::Relaxed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserProfile, CdnProvider, CoverTargetRotator, FlowShaper, OsProfile, StealthPacketClass,
    };
    use qf_common::time_source::ProtocolClock;
    use std::time::{Duration, Instant};

    #[test]
    fn cover_target_rotation_is_deterministic_and_empty_falls_back() {
        let rotator = CoverTargetRotator::new(vec!["a.example".into(), "b.example".into()]);
        assert_eq!(rotator.next_cover_target(), "a.example");
        assert_eq!(rotator.next_cover_target(), "b.example");
        assert_eq!(rotator.next_cover_target(), "a.example");
        assert_eq!(CoverTargetRotator::new(Vec::new()).next_cover_target(), "cdn.cloudflare.com");
    }

    #[test]
    fn provider_catalogs_have_expected_domains() {
        let rotator = CoverTargetRotator::from_providers(vec![CdnProvider::Cloudflare]);
        assert!(rotator.targets().iter().any(|target| target.contains("cloudflare")));
        assert!(CoverTargetRotator::broad_providers().targets().len() >= 20);
    }

    #[test]
    fn flow_shaper_clamps_jitter_and_paces_handshakes() {
        let shaper = FlowShaper::new(0, false);
        assert_eq!(shaper.apply_jitter(), Duration::from_micros(1));
        assert_eq!(shaper.apply_flight_pacing(false), Duration::ZERO);
        assert_eq!(shaper.apply_flight_pacing(true), Duration::from_millis(15));
    }

    #[test]
    fn flow_history_stays_bounded() {
        let shaper = FlowShaper::new(100, false);
        for size in 0..300 {
            shaper.record_and_prune(size, StealthPacketClass::Data);
        }
        assert!(shaper.history_len() <= 256);
    }

    #[test]
    fn flow_shaper_widens_jitter_at_burst_edges() {
        // TODO-1010 (WF-A2D): burst-interior packets keep the tight range,
        // the first packet after an idle gap must sample the full range -
        // burst boundaries carry the fingerprint, not the interior.
        use qf_common::time_source::test_support::ManualTimeSource;
        use std::time::SystemTime;

        let clock_src = ManualTimeSource::new(Instant::now(), SystemTime::now());
        let clock = ProtocolClock::from_source(clock_src.clone());
        let shaper = FlowShaper::new_with_clock(1_000, false, &clock);

        // Interior burst: >=32 packets with 2 ms gaps in the history window.
        for _ in 0..40 {
            shaper.record_and_prune(1_200, StealthPacketClass::Data);
            clock_src.advance(Duration::from_millis(2));
        }
        for _ in 0..64 {
            let jitter = shaper.apply_jitter();
            assert!(
                jitter <= Duration::from_micros(500),
                "interior burst jitter {jitter:?} must stay in the low half"
            );
        }

        // Edge: a 500 ms idle gap makes the next packet a train boundary.
        // The full range becomes reachable, so at least one sample out of
        // many must exceed the tight interior ceiling.
        clock_src.advance(Duration::from_millis(500));
        let mut saw_wide = false;
        for _ in 0..256 {
            if shaper.apply_jitter() > Duration::from_micros(500) {
                saw_wide = true;
                break;
            }
        }
        assert!(saw_wide, "burst-edge packet never sampled the wide jitter range");
    }

    #[test]
    fn persona_enums_are_exposed_by_the_stealth_leaf() {
        assert_eq!("firefox".parse(), Ok(BrowserProfile::Firefox));
        assert_eq!("mac".parse(), Ok(OsProfile::MacOS));
    }
}
