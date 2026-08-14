use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// GeoIP blocking.
//
// Uses the `maxminddb` crate to look up the country of an IP address in a
// MaxMindDB GeoLite2 (or GeoIP2) country database. IPs mapping to a blocked
// country are rejected. A configured database is a startup dependency: the
// server must not silently continue with an inactive policy.
// ---------------------------------------------------------------------------

/// Configuration for GeoIP-based country blocking.
#[derive(Clone, Debug, Default)]
pub struct GeoIpConfig {
    /// Path to a MaxMindDB GeoLite2 (or equivalent) country database.
    pub db_path: Option<PathBuf>,
    /// ISO country codes to block (e.g. "CN", "RU", "KP").
    pub blocked_countries: HashSet<String>,
}

impl GeoIpConfig {
    /// Validate the activation contract without touching the database.
    pub fn validate(&self) -> Result<(), GeoIpError> {
        match (self.db_path.is_some(), self.blocked_countries.is_empty()) {
            (false, true) => return Ok(()),
            (false, false) => return Err(GeoIpError::DatabasePathRequired),
            (true, true) => return Err(GeoIpError::BlockedCountriesRequired),
            (true, false) => {}
        }

        for country in &self.blocked_countries {
            if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
                return Err(GeoIpError::InvalidCountryCode(country.clone()));
            }
        }
        Ok(())
    }

    /// Whether both a database path and at least one blocked country are configured.
    pub fn is_enabled(&self) -> bool {
        self.db_path.is_some() && !self.blocked_countries.is_empty()
    }
}

/// Actual GeoIP activation state exposed by runtime status and metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GeoIpStatus {
    Disabled = 0,
    Active = 1,
    Failed = 2,
}

impl GeoIpStatus {
    /// Stable status label for logs, JSON, and Prometheus labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Active => "active",
            Self::Failed => "failed",
        }
    }
}

/// Typed startup failures for configured GeoIP activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoIpError {
    /// A country policy was configured without a database path.
    DatabasePathRequired,
    /// A database path was configured without at least one country code.
    BlockedCountriesRequired,
    /// A country code is not an uppercase ISO 3166-1 alpha-2 code.
    InvalidCountryCode(String),
    /// The configured path does not exist.
    MissingDatabase(PathBuf),
    /// The database file exists but is empty.
    EmptyDatabase(PathBuf),
    /// The database path cannot be read or is not a regular file.
    UnreadableDatabase { path: PathBuf, reason: String },
    /// The MaxMind database is malformed or failed full structural verification.
    InvalidDatabase { path: PathBuf, reason: String },
    /// The database is valid MaxMind data but is not a country database.
    UnsupportedDatabase { path: PathBuf, database_type: String },
}

impl std::fmt::Display for GeoIpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DatabasePathRequired => {
                formatter.write_str("GeoIP blocked countries require a database path")
            }
            Self::BlockedCountriesRequired => {
                formatter.write_str("GeoIP database path requires at least one blocked country")
            }
            Self::InvalidCountryCode(code) => write!(
                formatter,
                "invalid GeoIP country code {code:?}; expected uppercase ISO 3166-1 alpha-2"
            ),
            Self::MissingDatabase(path) => {
                write!(formatter, "GeoIP database is missing: {}", path.display())
            }
            Self::EmptyDatabase(path) => {
                write!(formatter, "GeoIP database is empty: {}", path.display())
            }
            Self::UnreadableDatabase { path, reason } => write!(
                formatter,
                "GeoIP database is unreadable at {}: {reason}",
                path.display()
            ),
            Self::InvalidDatabase { path, reason } => write!(
                formatter,
                "GeoIP database is invalid at {}: {reason}",
                path.display()
            ),
            Self::UnsupportedDatabase { path, database_type } => write!(
                formatter,
                "GeoIP database at {} has unsupported type {database_type:?}; expected a country database",
                path.display()
            ),
        }
    }
}

impl std::error::Error for GeoIpError {}

/// Bounded lookup/decode failures after a database was activated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoIpLookupError {
    /// The MaxMind search tree could not resolve the source address.
    Lookup { ip: IpAddr, reason: String },
    /// The matched record could not be decoded as a country record.
    Decode { ip: IpAddr, reason: String },
    /// A matched record had no country payload or ISO code.
    MissingCountryRecord { ip: IpAddr },
}

impl std::fmt::Display for GeoIpLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lookup { ip, reason } => {
                write!(formatter, "GeoIP lookup failed for {ip}: {reason}")
            }
            Self::Decode { ip, reason } => {
                write!(formatter, "GeoIP decode failed for {ip}: {reason}")
            }
            Self::MissingCountryRecord { ip } => {
                write!(formatter, "GeoIP record for {ip} has no country ISO code")
            }
        }
    }
}

impl std::error::Error for GeoIpLookupError {}

/// GeoIP-based source-IP blocker.
///
/// Loads and fully verifies a MaxMindDB country database during construction
/// and performs bounded lookups per IP. When no policy is configured, the
/// blocker is disabled and lookup is a zero-cost allow path.
pub struct GeoIpBlocker {
    config: GeoIpConfig,
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpBlocker {
    /// Validate and activate a blocker from the given config.
    pub fn try_new(config: GeoIpConfig) -> Result<Self, GeoIpError> {
        config.validate()?;
        let Some(path) = config.db_path.as_ref() else {
            return Ok(Self { config, reader: None });
        };

        let metadata = std::fs::metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                GeoIpError::MissingDatabase(path.clone())
            } else {
                GeoIpError::UnreadableDatabase { path: path.clone(), reason: error.to_string() }
            }
        })?;
        if !metadata.is_file() {
            return Err(GeoIpError::UnreadableDatabase {
                path: path.clone(),
                reason: "path is not a regular file".to_string(),
            });
        }
        if metadata.len() == 0 {
            return Err(GeoIpError::EmptyDatabase(path.clone()));
        }

        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|error| map_geoip_database_error(path, error))?;
        reader.verify().map_err(|error| GeoIpError::InvalidDatabase {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        let database_type = reader.metadata().database_type.clone();
        if !database_type.to_ascii_lowercase().contains("country") {
            return Err(GeoIpError::UnsupportedDatabase { path: path.clone(), database_type });
        }

        log::info!(
            "GeoIP: active country database loaded from {} with {} blocked countries",
            path.display(),
            config.blocked_countries.len()
        );
        Ok(Self { config, reader: Some(reader) })
    }

    /// Create a blocker with no database and no blocked countries (no-op).
    pub fn disabled() -> Self {
        Self { config: GeoIpConfig::default(), reader: None }
    }

    /// Whether the country database was actually loaded and verified.
    pub fn is_enabled(&self) -> bool {
        self.reader.is_some()
    }

    /// Return the actual loaded-policy state.
    pub fn status(&self) -> GeoIpStatus {
        if self.is_enabled() {
            GeoIpStatus::Active
        } else {
            GeoIpStatus::Disabled
        }
    }

    /// Evaluate one source address. Lookup/decode failures are returned so the
    /// admission caller can drop the packet and record explicit telemetry.
    pub fn lookup(&self, ip: IpAddr) -> Result<bool, GeoIpLookupError> {
        let Some(reader) = self.reader.as_ref() else {
            return Ok(false);
        };

        let lookup_result = reader
            .lookup(ip)
            .map_err(|error| GeoIpLookupError::Lookup { ip, reason: error.to_string() })?;
        if !lookup_result.has_data() {
            return Ok(false);
        }
        let country = lookup_result
            .decode::<maxminddb::geoip2::Country>()
            .map_err(|error| GeoIpLookupError::Decode { ip, reason: error.to_string() })?
            .ok_or(GeoIpLookupError::MissingCountryRecord { ip })?;
        let Some(iso_code) = country.country.iso_code else {
            return Err(GeoIpLookupError::MissingCountryRecord { ip });
        };
        Ok(self.config.blocked_countries.contains(iso_code))
    }

    /// Returns `true` if the IP maps to a blocked country. A lookup failure is
    /// fail-closed for callers that cannot carry typed error telemetry.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.lookup(ip).unwrap_or(true)
    }

    /// Borrow the configured blocked-country set.
    pub fn blocked_countries(&self) -> &HashSet<String> {
        &self.config.blocked_countries
    }
}

fn map_geoip_database_error(
    path: &std::path::Path,
    error: maxminddb::MaxMindDbError,
) -> GeoIpError {
    match error {
        maxminddb::MaxMindDbError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            GeoIpError::MissingDatabase(path.to_path_buf())
        }
        maxminddb::MaxMindDbError::Io(error) => {
            GeoIpError::UnreadableDatabase { path: path.to_path_buf(), reason: error.to_string() }
        }
        error => {
            GeoIpError::InvalidDatabase { path: path.to_path_buf(), reason: error.to_string() }
        }
    }
}
