use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use fec::FecMode;
use stealth::BrowserProfile;
use core as quic_core;
use quic_core::{
    QuicLimits, DEFAULT_MIN_MTU, DEFAULT_MAX_MTU, DEFAULT_PROBE_TIMEOUT_MS,
    DEFAULT_PERIODIC_PROBE_INTERVAL_MS,
};

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug, Serialize, Deserialize)]
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Serialize, Deserialize)]
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

#[derive(Parser, Debug, Serialize, Deserialize)]
#[command(author, version, about="QuicFuscate VPN - QUIC mit uTLS Integration", long_about=None)]
pub struct CommandLineOptions {
    /// Server-Hostname oder IP-Adresse
    #[arg(short, long, alias = "host", default_value = "example.com")]
    pub server: String,

    /// Server-Port
    #[arg(short, long, default_value_t = 443)]
    pub port: u16,

    /// Pfad zur Konfigurationsdatei
    #[arg(long)]
    pub config: Option<std::path::PathBuf>,

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

impl Default for CommandLineOptions {
    fn default() -> Self {
        Self {
            server: "example.com".into(),
            port: 443,
            config: None,
            fingerprint: Fingerprint::Chrome,
            no_utls: false,
            verify_peer: false,
            ca_file: None,
            verbose: false,
            fec: FecCliMode::Adaptive,
            fec_ratio: 5.0,
            debug_tls: false,
            list_fingerprints: false,
            domain_fronting: false,
            http3_masq: false,
            doh: false,
            spin_random: false,
            spin_probability: 0.5,
            zero_rtt: false,
            zero_rtt_max: 1024,
            min_mtu: DEFAULT_MIN_MTU,
            max_mtu: DEFAULT_MAX_MTU,
            probe_timeout: DEFAULT_PROBE_TIMEOUT_MS,
            probe_interval: DEFAULT_PERIODIC_PROBE_INTERVAL_MS,
        }
    }
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

    /// Load options from the given TOML configuration file.
    /// Fields not provided on the command line will be filled from the file.
    pub fn merge_config(mut self) -> Result<Self, Box<dyn std::error::Error>> {
        let path = match &self.config {
            Some(p) => p,
            None => return Ok(self),
        };
        let contents = std::fs::read_to_string(path)?;
        let file_opts: CommandLineOptions = toml::from_str(&contents)?;
        let defaults = CommandLineOptions::default();

        macro_rules! maybe_use {
            ($field:ident) => {
                if self.$field == defaults.$field {
                    self.$field = file_opts.$field;
                }
            };
        }

        maybe_use!(server);
        maybe_use!(port);
        maybe_use!(fingerprint);
        maybe_use!(no_utls);
        maybe_use!(verify_peer);
        maybe_use!(ca_file);
        maybe_use!(verbose);
        maybe_use!(fec);
        maybe_use!(fec_ratio);
        maybe_use!(debug_tls);
        maybe_use!(list_fingerprints);
        maybe_use!(domain_fronting);
        maybe_use!(http3_masq);
        maybe_use!(doh);
        maybe_use!(spin_random);
        maybe_use!(spin_probability);
        maybe_use!(zero_rtt);
        maybe_use!(zero_rtt_max);
        maybe_use!(min_mtu);
        maybe_use!(max_mtu);
        maybe_use!(probe_timeout);
        maybe_use!(probe_interval);

        Ok(self)
    }
}
