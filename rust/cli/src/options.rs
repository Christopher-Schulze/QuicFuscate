use clap::{Parser, ValueEnum};

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

    /// TLS-Debug-Informationen anzeigen
    #[arg(long, default_value_t = false)]
    pub debug_tls: bool,

    /// Zeigt verfügbare Browser-Fingerprints an
    #[arg(long)]
    pub list_fingerprints: bool,
}
