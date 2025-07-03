use clap::{Parser, ValueEnum};
use fec::FecMode;
use stealth::BrowserProfile;
use core as quic_core;
use quic_core::{
    QuicLimits, DEFAULT_MIN_MTU, DEFAULT_MAX_MTU, DEFAULT_PROBE_TIMEOUT_MS,
    DEFAULT_PERIODIC_PROBE_INTERVAL_MS,
};

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum FecCliMode {
    Off,
    Performance,
    Always,
    Adaptive,
}

impl From<FecCliMode> for FecMode {
    fn from(m: FecCliMode) -> Self {
        match m {
            FecCliMode::Off => FecMode::Performance,
            FecCliMode::Performance => FecMode::Performance,
            FecCliMode::Always => FecMode::AlwaysOn,
            FecCliMode::Adaptive => FecMode::Adaptive,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum Fingerprint {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Brave,
    Opera,
    ChromeAndroid,
    SafariIos,
    Random,
}

impl From<Fingerprint> for BrowserProfile {
    fn from(fp: Fingerprint) -> Self {
        match fp {
            Fingerprint::Chrome | Fingerprint::Brave | Fingerprint::Opera | Fingerprint::ChromeAndroid => BrowserProfile::Chrome,
            Fingerprint::Firefox => BrowserProfile::Firefox,
            Fingerprint::Safari | Fingerprint::SafariIos => BrowserProfile::Safari,
            Fingerprint::Edge => BrowserProfile::Edge,
            Fingerprint::Random => BrowserProfile::Chrome,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about="QuicFuscate VPN - QUIC mit uTLS Integration", long_about=None)]
pub struct CommandLineOptions {
    /// Server-Hostname oder IP-Adresse
    #[arg(short, long, alias = "host", default_value = "example.com")]
    pub server: String,

    /// Server-Port
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,

    /// Browser-Fingerprint
    #[arg(short, long, value_enum, default_value_t = Fingerprint::Chrome)]
    pub fingerprint: Fingerprint,

    /// Deaktiviert uTLS (verwendet Standard-TLS)
    #[arg(long, default_value_t = false)]
    pub no_utls: bool,

    /// Aktiviert die Verifizierung des Server-Zertifikats
    #[arg(long, default_value_t = false)]
    pub verify_peer: bool,

    /// Pfad zur CA-Zertifikatsdatei (für Peer-Verifizierung)
    #[arg(long)]
    pub ca_file: Option<String>,

    /// Ausführliche Protokollierung
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// FEC Mode
    #[arg(long, value_enum, default_value_t = FecCliMode::Adaptive)]
    pub fec: FecCliMode,

    /// Ratio used when --fec always <ratio>
    #[arg(long, default_value_t = 5.0)]
    pub fec_ratio: f32,

    /// TLS-Debug-Informationen anzeigen
    #[arg(long, default_value_t = false)]
    pub debug_tls: bool,

    /// Zeigt verfügbare Browser-Fingerprints an
    #[arg(long)]
    pub list_fingerprints: bool,

    /// Enable domain fronting
    #[arg(long, default_value_t = false)]
    pub domain_fronting: bool,

    /// Enable HTTP/3 masquerading
    #[arg(long, default_value_t = false)]
    pub http3_masq: bool,

    /// Enable DNS over HTTPS
    #[arg(long, default_value_t = false)]
    pub doh: bool,

    /// Enable spinbit randomization
    #[arg(long, default_value_t = false)]
    pub spin_random: bool,

    /// Probability for spinbit flipping
    #[arg(long, default_value_t = 0.5)]
    pub spin_probability: f64,

    /// Enable Zero-RTT data
    #[arg(long, default_value_t = false)]
    pub zero_rtt: bool,

    /// Maximum bytes allowed for Zero-RTT data
    #[arg(long, default_value_t = 1024)]
    pub zero_rtt_max: usize,

    /// Minimum MTU for path discovery
    #[arg(long, default_value_t = DEFAULT_MIN_MTU)]
    pub min_mtu: u16,

    /// Maximum MTU for path discovery
    #[arg(long, default_value_t = DEFAULT_MAX_MTU)]
    pub max_mtu: u16,

    /// Timeout in milliseconds for outstanding probes
    #[arg(long, default_value_t = DEFAULT_PROBE_TIMEOUT_MS)]
    pub probe_timeout: u32,

    /// Interval in milliseconds between periodic probes
    #[arg(long, default_value_t = DEFAULT_PERIODIC_PROBE_INTERVAL_MS)]
    pub probe_interval: u32,
}

impl CommandLineOptions {
    /// Construct a [`QuicLimits`] instance from CLI options.
    pub fn to_limits(&self) -> QuicLimits {
        QuicLimits {
            min_mtu: self.min_mtu,
            max_mtu: self.max_mtu,
            initial_mtu: quic_core::DEFAULT_INITIAL_MTU,
            mtu_step: quic_core::DEFAULT_MTU_STEP_SIZE,
            probe_timeout_ms: self.probe_timeout,
            periodic_probe_interval_ms: self.probe_interval,
        }
    }
}
