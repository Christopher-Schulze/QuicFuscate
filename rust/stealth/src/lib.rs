//! High level traffic obfuscation utilities.

pub mod browser;
pub mod datagram;
pub mod doh;
pub mod domain_fronting;
pub mod fake_tls;
pub mod http3_masq;
pub mod qpack;
pub mod spinbit;
pub mod stream;
pub mod xor;
pub mod zero_rtt;

pub use browser::{BrowserFingerprint, BrowserProfile, BrowserType, OperatingSystem};
use datagram::DatagramEngine;
use doh::{DohClient, DohConfig};
use domain_fronting::{SniConfig, SniHiding};
use fake_tls::FakeTls;
use http3_masq::Masquerade;
use qpack::QpackEngine;
use spinbit::SpinBitRandomizer;
use stream::StreamEngine;
pub use xor::{XORConfig, XORObfuscator, XORPattern};
use zero_rtt::ZeroRttEngine;

pub struct QuicFuscateStealth {
    pub qpack: QpackEngine,
    pub zero_rtt: ZeroRttEngine,
    pub datagram: DatagramEngine,
    pub stream: StreamEngine,
    pub spin: SpinBitRandomizer,
    pub domain_fronting: SniHiding,
    pub http3_masq: Masquerade,
    pub doh: DohClient,
    pub tls: FakeTls,
}

impl Default for QuicFuscateStealth {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicFuscateStealth {
    pub fn new() -> Self {
        Self {
            qpack: QpackEngine::new(),
            zero_rtt: ZeroRttEngine::new(),
            datagram: DatagramEngine::new(),
            stream: StreamEngine::new(),
            spin: SpinBitRandomizer::new(),
            domain_fronting: SniHiding::new(SniConfig::default()),
            http3_masq: Masquerade::new(BrowserProfile::Chrome),
            doh: DohClient::new(DohConfig::default()),
            tls: FakeTls::new(BrowserProfile::Chrome),
        }
    }

    pub fn initialize(&self) -> bool {
        true
    }

    pub fn shutdown(&self) {}

    pub fn randomize_spinbit(&self, bit: bool) -> bool {
        self.spin.randomize(bit)
    }

    pub fn enable_spinbit(&mut self, e: bool) {
        self.spin.enable(e);
    }
    pub fn set_spinbit_probability(&mut self, p: f64) {
        self.spin.set_probability(p);
    }
    pub fn enable_utls(&mut self, e: bool) {
        self.tls.enable(e);
    }
    pub fn set_browser_profile(&mut self, profile: BrowserProfile) {
        self.http3_masq.set_profile(profile);
        self.tls.set_profile(profile);
    }
    pub fn enable_domain_fronting(&mut self, e: bool) {
        self.domain_fronting.enable(e);
    }
    pub fn enable_http3_masq(&mut self, e: bool) {
        self.http3_masq.enable(e);
    }
    pub fn enable_doh(&mut self, e: bool) {
        self.doh.enable(e);
    }
    pub fn enable_zero_rtt(&mut self, e: bool) {
        self.zero_rtt.set_enabled(e);
    }
    pub fn set_zero_rtt_max_early_data(&mut self, max: usize) {
        self.zero_rtt.set_max_early_data(max);
    }

    pub async fn resolve_domain(&mut self, domain: &str) -> std::net::IpAddr {
        self.doh.resolve(domain).await
    }

    pub fn generate_client_hello(&self) -> Vec<u8> {
        self.tls.generate_client_hello()
    }

    pub fn apply_domain_fronting(&self, headers: &str) -> String {
        self.domain_fronting.apply_domain_fronting(headers)
    }
}
