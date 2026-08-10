//! Root-independent stealth helpers shared by the product stealth manager.
//!
//! The root package keeps compatibility projections for the historical private
//! types while this crate owns domain-fronting rotation and flow-shaping state.

#[doc(hidden)]
pub use config::{PaddingStrategy, RotationMode, StealthMode};
#[doc(hidden)]
pub use domain_fronting::{CdnProvider, DomainFrontingManager};
#[doc(hidden)]
pub use fingerprint::{
    update_ip_checksum_incremental, update_tcp_checksum_incremental, IcmpUnreachablePolicy,
    IpIdBehavior, NormalizeOutcome, NormalizeResult, OsFingerprintProfile, PacketNormalizer,
};
#[doc(hidden)]
pub use flow_shaping::{FlowShaper, StealthPacketClass};
#[doc(hidden)]
pub use profiles::{parse_profile_slot, BrowserProfile, OsProfile};
#[doc(hidden)]
pub use rotation::FingerprintRotationConfig;
#[doc(hidden)]
pub use tls_client_hello::TlsClientHelloProfileCatalog;
#[doc(hidden)]
pub use tls_cover::{TlsCover, TlsCoverCipherSuite};
#[doc(hidden)]
pub use tls_profile::TlsProfile;
#[doc(hidden)]
pub use traffic::{RateChoker, ServerPushState, ServerPushTriggerReason};

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
pub mod fingerprint;
#[doc(hidden)]
pub mod probe_detector;
#[doc(hidden)]
pub mod profiles;
#[doc(hidden)]
pub mod rotation;
#[doc(hidden)]
mod tls_client_hello;
#[doc(hidden)]
pub mod tls_cover;
#[doc(hidden)]
pub mod tls_profile;
#[doc(hidden)]
pub mod traffic;

mod domain_fronting {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const DEFAULT_FRONTING_DOMAIN: &str = "cdn.cloudflare.com";

    /// Supported CDN providers for domain-fronting rotation.
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

    /// Thread-safe domain rotation for configured or built-in CDN domains.
    #[doc(hidden)]
    pub struct DomainFrontingManager {
        domains: Arc<[String]>,
        index: AtomicUsize,
    }

    impl DomainFrontingManager {
        /// Create a manager from an explicit domain list.
        #[inline]
        #[doc(hidden)]
        pub fn new(domains: Vec<String>) -> Self {
            Self { domains: Arc::from(domains), index: AtomicUsize::new(0) }
        }

        /// Create a manager from all domains exposed by the given providers.
        #[inline]
        #[doc(hidden)]
        pub fn from_providers(providers: Vec<CdnProvider>) -> Self {
            let domains = providers
                .into_iter()
                .flat_map(|provider| provider.domains().into_iter().map(str::to_owned))
                .collect();
            Self::new(domains)
        }

        /// Create the built-in broad provider rotation.
        #[inline]
        #[doc(hidden)]
        pub fn ultra_stealth() -> Self {
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

        /// Select the next configured domain using strict round-robin order.
        #[inline]
        #[doc(hidden)]
        pub fn get_fronted_domain(&self) -> String {
            if self.domains.is_empty() {
                return DEFAULT_FRONTING_DOMAIN.to_owned();
            }
            let current = self.index.fetch_add(1, Ordering::Relaxed);
            self.domains[current % self.domains.len()].clone()
        }

        /// Return the configured domains for compatibility projections and tests.
        #[inline]
        #[doc(hidden)]
        pub fn domains(&self) -> &[String] {
            &self.domains
        }

        /// Select a random configured domain, falling back to the Cloudflare default.
        #[inline]
        #[allow(dead_code)]
        #[doc(hidden)]
        pub fn random_domain(&self) -> String {
            use rand::seq::IndexedRandom;
            let mut rng = rand::rng();
            self.domains
                .as_ref()
                .choose(&mut rng)
                .cloned()
                .unwrap_or_else(|| DEFAULT_FRONTING_DOMAIN.to_owned())
        }
    }
}

mod flow_shaping {
    use qf_common::time_source::ProtocolClock;
    use rand::Rng;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Stealth packet class tracked by the flow-shaping history.
    #[derive(Clone, Copy)]
    #[allow(dead_code)]
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
        _enabled: AtomicBool,
    }

    impl FlowShaper {
        /// Create a shaper using the process clock.
        #[allow(dead_code)]
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
                _enabled: AtomicBool::new(true),
            }
        }

        /// Return a random jitter delay within the configured range.
        #[doc(hidden)]
        pub fn apply_jitter(&self) -> Duration {
            let jitter_us = rand::rng().random_range(self.jitter_min_us..=self.jitter_max_us);
            Duration::from_micros(jitter_us)
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
        }

        /// Return the current bounded history length for diagnostics and tests.
        #[doc(hidden)]
        pub fn history_len(&self) -> usize {
            self.packet_history.lock().map(|history| history.len()).unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserProfile, CdnProvider, DomainFrontingManager, FlowShaper, OsProfile,
        StealthPacketClass,
    };
    use std::time::Duration;

    #[test]
    fn domain_rotation_is_deterministic_and_empty_falls_back() {
        let manager = DomainFrontingManager::new(vec!["a.example".into(), "b.example".into()]);
        assert_eq!(manager.get_fronted_domain(), "a.example");
        assert_eq!(manager.get_fronted_domain(), "b.example");
        assert_eq!(manager.get_fronted_domain(), "a.example");
        assert_eq!(
            DomainFrontingManager::new(Vec::new()).get_fronted_domain(),
            "cdn.cloudflare.com"
        );
    }

    #[test]
    fn provider_catalogs_have_expected_domains() {
        let manager = DomainFrontingManager::from_providers(vec![CdnProvider::Cloudflare]);
        assert!(manager.domains().iter().any(|domain| domain.contains("cloudflare")));
        assert!(DomainFrontingManager::ultra_stealth().domains().len() >= 20);
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
    fn persona_enums_are_exposed_by_the_stealth_leaf() {
        assert_eq!("firefox".parse(), Ok(BrowserProfile::Firefox));
        assert_eq!("mac".parse(), Ok(OsProfile::MacOS));
    }
}
