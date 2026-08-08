//! Production PKI — CA hierarchy, certificate generation, and chain validation (TODO-434).
//!
//! Replaces the ephemeral self-signed certificate fallback with a proper
//! CA hierarchy: a root CA (long-lived, offline) signs an intermediate CA
//! (online, used for signing server leaf certificates). Leaf certificates
//! are validated against the full chain during TLS handshake.
//!
//! Hierarchy:
//!   Root CA (self-signed, 10y expiry)
//!     └── Intermediate CA (signed by Root, 5y expiry)
//!           └── Server leaf (signed by Intermediate, 1y expiry, SAN = server hostname/IP)
//!
//! All certificates use ECDSA P-256 (prime256v1) for modern compatibility.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Error type for PKI operations.
#[derive(Debug)]
pub enum PkiError {
    /// Certificate generation failed.
    GenerationFailed(String),
    /// The system clock could not provide a representable PKI timestamp.
    ClockError(String),
    /// A certificate validity interval is not strictly ordered.
    InvalidValidity(String),
    /// Certificate parsing failed.
    ParseFailed(String),
    /// Chain validation failed.
    ValidationFailed(String),
    /// A PKI output path is not safe to write through.
    UnsafePath(String),
    /// I/O error.
    IoError(std::io::Error),
    /// Feature not enabled (rcgen not compiled).
    FeatureNotEnabled,
}

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenerationFailed(s) => write!(f, "cert generation failed: {s}"),
            Self::ClockError(s) => write!(f, "PKI clock error: {s}"),
            Self::InvalidValidity(s) => write!(f, "invalid certificate validity: {s}"),
            Self::ParseFailed(s) => write!(f, "cert parse failed: {s}"),
            Self::ValidationFailed(s) => write!(f, "chain validation failed: {s}"),
            Self::UnsafePath(s) => write!(f, "unsafe PKI path: {s}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::FeatureNotEnabled => write!(f, "PKI feature not enabled (rcgen required)"),
        }
    }
}

impl std::error::Error for PkiError {}

impl From<std::io::Error> for PkiError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<rcgen::Error> for PkiError {
    fn from(e: rcgen::Error) -> Self {
        Self::GenerationFailed(e.to_string())
    }
}

/// Certificate validity period in days.
pub const ROOT_CA_VALIDITY_DAYS: u32 = 3650; // 10 years
pub const INTERMEDIATE_CA_VALIDITY_DAYS: u32 = 1825; // 5 years
pub const SERVER_LEAF_VALIDITY_DAYS: u32 = 365; // 1 year

/// One checked instant shared by PKI generation, validation, and quarantine.
#[derive(Debug, Clone, Copy)]
struct PkiTime {
    since_epoch: Duration,
    unix_time: rustls::pki_types::UnixTime,
}

trait PkiClock {
    fn now_system(&self) -> SystemTime;
}

struct CanonicalPkiClock;

impl PkiClock for CanonicalPkiClock {
    fn now_system(&self) -> SystemTime {
        crate::time_source::now_system()
    }
}

impl PkiTime {
    fn capture() -> Result<Self, PkiError> {
        Self::capture_from(&CanonicalPkiClock)
    }

    fn capture_from(clock: &dyn PkiClock) -> Result<Self, PkiError> {
        Self::from_system_time(clock.now_system())
    }

    fn from_system_time(now: SystemTime) -> Result<Self, PkiError> {
        let since_epoch = now.duration_since(UNIX_EPOCH).map_err(|error| {
            PkiError::ClockError(format!("system clock predates Unix epoch: {error}"))
        })?;
        Ok(Self {
            since_epoch,
            unix_time: rustls::pki_types::UnixTime::since_unix_epoch(since_epoch),
        })
    }

    #[cfg(feature = "rcgen")]
    fn offset_datetime(self) -> Result<time::OffsetDateTime, PkiError> {
        let timestamp_nanos = i128::try_from(self.since_epoch.as_nanos()).map_err(|_| {
            PkiError::ClockError("system clock timestamp exceeds the checked range".into())
        })?;
        time::OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos).map_err(|error| {
            PkiError::ClockError(format!("system clock timestamp is not representable: {error}"))
        })
    }

    fn quarantine_stamp(self) -> u128 {
        self.since_epoch.as_nanos()
    }
}

/// A generated certificate + its private key (DER-encoded).
///
/// The private key (`key_der`) is zeroized on drop via the `Drop`
/// implementation so that no CA key material (root, intermediate, or leaf)
/// lingers in memory after the owning `GeneratedCert` goes out of scope.
/// Certificates (`cert_der`) are public and not zeroized.
pub struct GeneratedCert {
    /// Certificate in DER format.
    pub cert_der: Vec<u8>,
    /// Private key in DER format.
    pub key_der: Vec<u8>,
}

impl Drop for GeneratedCert {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_der.zeroize();
    }
}

/// A complete CA hierarchy: root CA, intermediate CA, and server leaf.
pub struct CaHierarchy {
    pub root_ca: GeneratedCert,
    pub intermediate_ca: GeneratedCert,
    pub server_leaf: GeneratedCert,
}

/// Generate a full CA hierarchy with a server leaf certificate for the given
/// hostname or IP address. All certs are ECDSA P-256.
#[cfg(feature = "rcgen")]
pub fn generate_hierarchy(
    server_hostname: &str,
    organization: &str,
) -> Result<CaHierarchy, PkiError> {
    let pki_time = PkiTime::capture()?;
    generate_hierarchy_at(server_hostname, organization, pki_time)
}

#[cfg(feature = "rcgen")]
fn generate_hierarchy_at(
    server_hostname: &str,
    organization: &str,
    pki_time: PkiTime,
) -> Result<CaHierarchy, PkiError> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyUsagePurpose, SanType,
    };
    let now = pki_time.offset_datetime()?;

    // --- Root CA ---
    let mut root_params = CertificateParams::new(vec![])?;
    root_params.distinguished_name = DistinguishedName::new();
    root_params.distinguished_name.push(DnType::CountryName, "US");
    root_params.distinguished_name.push(DnType::OrganizationName, organization);
    root_params.distinguished_name.push(DnType::CommonName, format!("{organization} Root CA"));
    root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root_validity = checked_validity_window(
        now,
        time::Duration::days(i64::from(ROOT_CA_VALIDITY_DAYS)),
        "root CA",
    )?;
    root_params.not_before = root_validity.not_before;
    root_params.not_after = root_validity.not_after;
    let root_key = rcgen::KeyPair::generate()
        .map_err(|e| PkiError::GenerationFailed(format!("root key gen: {e}")))?;
    let root_cert = root_params
        .self_signed(&root_key)
        .map_err(|e| PkiError::GenerationFailed(format!("root cert: {e}")))?;

    // --- Intermediate CA ---
    let mut inter_params = CertificateParams::new(vec![])?;
    inter_params.distinguished_name = DistinguishedName::new();
    inter_params.distinguished_name.push(DnType::CountryName, "US");
    inter_params.distinguished_name.push(DnType::OrganizationName, organization);
    inter_params
        .distinguished_name
        .push(DnType::CommonName, format!("{organization} Intermediate CA"));
    inter_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    inter_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let intermediate_validity = checked_validity_window(
        now,
        time::Duration::days(i64::from(INTERMEDIATE_CA_VALIDITY_DAYS)),
        "intermediate CA",
    )?;
    inter_params.not_before = intermediate_validity.not_before;
    inter_params.not_after = intermediate_validity.not_after;
    let inter_key = rcgen::KeyPair::generate()
        .map_err(|e| PkiError::GenerationFailed(format!("intermediate key gen: {e}")))?;
    let inter_cert = inter_params
        .signed_by(&inter_key, &root_cert, &root_key)
        .map_err(|e| PkiError::GenerationFailed(format!("intermediate cert: {e}")))?;

    // --- Server Leaf ---
    let mut leaf_params = CertificateParams::new(vec![])?;
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params.distinguished_name.push(DnType::CountryName, "US");
    leaf_params.distinguished_name.push(DnType::OrganizationName, organization);
    leaf_params.distinguished_name.push(DnType::CommonName, server_hostname);
    // SANs: hostname + IP if it's an IP address.
    let mut sans = vec![];
    if let Ok(ip) = server_hostname.parse::<std::net::IpAddr>() {
        sans.push(SanType::IpAddress(ip));
    } else {
        let dns_name = rcgen::Ia5String::try_from(server_hostname)
            .map_err(|_| PkiError::GenerationFailed("invalid SAN hostname".into()))?;
        sans.push(SanType::DnsName(dns_name));
    }
    // Always include localhost for development.
    sans.push(SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    sans.push(SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    leaf_params.subject_alt_names = sans;
    leaf_params.extended_key_usages =
        vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    leaf_params.key_usages =
        vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    let leaf_validity = checked_validity_window(
        now,
        time::Duration::days(i64::from(SERVER_LEAF_VALIDITY_DAYS)),
        "server leaf",
    )?;
    leaf_params.not_before = leaf_validity.not_before;
    leaf_params.not_after = leaf_validity.not_after;
    let leaf_key = rcgen::KeyPair::generate()
        .map_err(|e| PkiError::GenerationFailed(format!("leaf key gen: {e}")))?;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &inter_cert, &inter_key)
        .map_err(|e| PkiError::GenerationFailed(format!("leaf cert: {e}")))?;

    Ok(CaHierarchy {
        root_ca: GeneratedCert {
            cert_der: root_cert.der().to_vec(),
            key_der: root_key.serialize_der(),
        },
        intermediate_ca: GeneratedCert {
            cert_der: inter_cert.der().to_vec(),
            key_der: inter_key.serialize_der(),
        },
        server_leaf: GeneratedCert {
            cert_der: leaf_cert.der().to_vec(),
            key_der: leaf_key.serialize_der(),
        },
    })
}

#[cfg(feature = "rcgen")]
#[derive(Debug, Clone, Copy)]
struct CertificateValidity {
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
}

#[cfg(feature = "rcgen")]
fn checked_validity_window(
    not_before: time::OffsetDateTime,
    duration: time::Duration,
    label: &str,
) -> Result<CertificateValidity, PkiError> {
    let not_after = not_before.checked_add(duration).ok_or_else(|| {
        PkiError::InvalidValidity(format!("{label} validity exceeds the representable range"))
    })?;
    if not_before >= not_after {
        return Err(PkiError::InvalidValidity(format!(
            "{label} not_before must precede not_after"
        )));
    }
    Ok(CertificateValidity { not_before, not_after })
}

/// Generate a full CA hierarchy (stub when rcgen is not enabled).
#[cfg(not(feature = "rcgen"))]
pub fn generate_hierarchy(
    _server_hostname: &str,
    _organization: &str,
) -> Result<CaHierarchy, PkiError> {
    Err(PkiError::FeatureNotEnabled)
}

/// Report whether a path exists without following a final symlink.
///
/// `Path::exists()` resolves the link, so a dangling symlink reports absent and a
/// link to an unrelated file reports the target's existence. Both readings are wrong
/// for PKI material: the question is whether something occupies the name we intend
/// to create, not what it points at.
fn path_exists_no_follow(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Reject a PKI output path that is a symlink, without following it.
fn reject_symlinked_output(path: &Path) -> Result<(), PkiError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(PkiError::UnsafePath(format!(
            "{} is a symlink; PKI material is never written through a link",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PkiError::IoError(error)),
    }
}

/// Write PKI material to `path` without ever following a symlink at that name.
///
/// The content is created in a fresh sibling file that cannot pre-exist, is flushed
/// to disk, and is then renamed onto the target. `rename` does not follow a symlink
/// at its final component, so even if a link is planted between the check and the
/// rename the link itself is replaced and the write never reaches the attacker's
/// target. Checking `is_symlink()` and then reopening the same pathname for writing
/// would be the unsound version of this, and is deliberately not what happens here:
/// the rejection reports an existing link, and the rename is what makes the write
/// itself safe.
///
/// `mode` is applied at creation on Unix, so private key bytes are never briefly
/// readable under a wider mode.
fn write_pki_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), PkiError> {
    reject_symlinked_output(path)?;
    let parent =
        path.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or_else(|| {
            PkiError::UnsafePath(format!("{} has no parent directory", path.display()))
        })?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() {
        return Err(PkiError::UnsafePath(format!("{} is not a directory", parent.display())));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| PkiError::UnsafePath(format!("{} has no file name", path.display())))?;

    let temp_path = create_pki_temp_file(parent, file_name, contents, mode)?;
    if let Err(error) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(PkiError::IoError(error));
    }
    // Persist the directory entry itself, so a crash cannot leave the name pointing
    // at nothing after the content was already durable.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Create the staging file for [`write_pki_file`] and return its path.
///
/// The name must not already exist, so `create_new` both prevents reuse of an
/// attacker-planted file and turns a name collision into an error instead of an
/// overwrite. `O_NOFOLLOW` makes the creation refuse a symlink outright.
fn create_pki_temp_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
    contents: &[u8],
    mode: u32,
) -> Result<std::path::PathBuf, PkiError> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let mut last_error = None;
    for _ in 0..PKI_TEMP_NAME_ATTEMPTS {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = file_name.to_os_string();
        temp_name.push(format!(".tmp-{}-{unique}", std::process::id()));
        let temp_path = parent.join(temp_name);

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode).custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(not(unix))]
        let _ = mode;

        let mut file = match options.open(&temp_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(PkiError::IoError(error)),
        };
        let written = file.write_all(contents).and_then(|()| file.sync_all());
        if let Err(error) = written {
            drop(file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(PkiError::IoError(error));
        }
        return Ok(temp_path);
    }
    Err(PkiError::IoError(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AlreadyExists, "PKI staging name is unavailable")
    })))
}

/// How many staging names to try before reporting the directory unusable.
const PKI_TEMP_NAME_ATTEMPTS: u32 = 16;

/// Write a private key to disk in PEM format with restrictive permissions
/// (0600 on Unix). The intermediate PEM string copy is wrapped in
/// `Zeroizing<String>` so it is scrubbed on every exit path — including
/// early returns from `?` operators — without relying on the caller to
/// remember an explicit zeroize call. The caller's `key_der` slice is
/// also zeroized in place on the success path (and is additionally
/// protected by `GeneratedCert::drop` if the caller owns one). The
/// `zeroize` crate uses volatile writes to defeat dead-store elimination.
///
/// Note: `GeneratedCert::drop` also zeroizes `key_der`, so even if a
/// caller forgets to call this function the key is still scrubbed when the
/// `GeneratedCert` is dropped.
pub fn write_key_pem(key_der: &mut [u8], key_path: &Path) -> Result<(), PkiError> {
    use zeroize::Zeroize;

    // Zeroizing<String> guarantees the PEM-encoded key material is scrubbed
    // via volatile writes on drop, regardless of which `?` early-returns.
    let key_pem = zeroize::Zeroizing::new(der_to_pem(key_der, "PRIVATE KEY"));

    // The staging file is created with mode 0600, so the private key is never
    // briefly readable under a wider mode, and the write never follows a symlink
    // at the target name.
    write_pki_file(key_path, key_pem.as_bytes(), PKI_KEY_MODE)?;

    // Zeroize the caller's key_der slice on the success path. On early
    // return, GeneratedCert::drop (if the caller owns one) still scrubs it.
    key_der.zeroize();

    Ok(())
}

/// Private keys are readable only by the owning account.
const PKI_KEY_MODE: u32 = 0o600;
/// Certificates are public material and stay world-readable.
const PKI_CERT_MODE: u32 = 0o644;

/// Write a certificate chain (leaf + intermediate) to a single PEM file.
pub fn write_cert_chain_pem(
    leaf_der: &[u8],
    intermediate_der: &[u8],
    chain_path: &Path,
) -> Result<(), PkiError> {
    let mut chain_pem = der_to_pem(leaf_der, "CERTIFICATE");
    chain_pem.push_str(&der_to_pem(intermediate_der, "CERTIFICATE"));
    write_pki_file(chain_path, chain_pem.as_bytes(), PKI_CERT_MODE)
}

/// Write a CA certificate to disk in PEM format.
pub fn write_ca_cert_pem(ca_der: &[u8], ca_path: &Path) -> Result<(), PkiError> {
    let pem = der_to_pem(ca_der, "CERTIFICATE");
    write_pki_file(ca_path, pem.as_bytes(), PKI_CERT_MODE)
}

fn parse_certificates(
    pem: &[u8],
    path: &Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, PkiError> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};

    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PkiError::ParseFailed(format!("{}: {error}", path.display())))?;
    if certificates.is_empty() {
        return Err(PkiError::ParseFailed(format!(
            "{}: certificate chain is empty",
            path.display()
        )));
    }
    Ok(certificates)
}

fn validate_existing_pki_at(
    pki_dir: &Path,
    server_hostname: &str,
    pki_time: PkiTime,
) -> Result<(), PkiError> {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer, ServerName};
    use rustls::RootCertStore;
    use std::sync::Arc;
    let validation_time = pki_time.unix_time;

    let server_cert_path = pki_dir.join("server.crt");
    let server_key_path = pki_dir.join("server.key");
    let root_ca_path = pki_dir.join("ca-root.crt");
    let intermediate_ca_path = pki_dir.join("ca-intermediate.crt");

    let server_cert_pem = std::fs::read(&server_cert_path)?;
    let server_key_pem = std::fs::read(&server_key_path)?;
    let root_ca_pem = std::fs::read(&root_ca_path)?;
    let intermediate_ca_pem = std::fs::read(&intermediate_ca_path)?;
    let server_chain = parse_certificates(&server_cert_pem, &server_cert_path)?;
    if server_chain.len() < 2 {
        return Err(PkiError::ValidationFailed(
            "server certificate chain must contain a leaf and an intermediate".to_string(),
        ));
    }
    let intermediate_certificates =
        parse_certificates(&intermediate_ca_pem, &intermediate_ca_path)?;
    if intermediate_certificates.len() != 1
        || intermediate_certificates[0].as_ref() != server_chain[1].as_ref()
    {
        return Err(PkiError::ValidationFailed(
            "standalone intermediate certificate does not match the server chain".to_string(),
        ));
    }
    let root_certificates = parse_certificates(&root_ca_pem, &root_ca_path)?;
    if root_certificates.len() != 1 {
        return Err(PkiError::ValidationFailed(format!(
            "{} must contain exactly one trust anchor",
            root_ca_path.display()
        )));
    }

    let private_key = PrivateKeyDer::from_pem_slice(&server_key_pem).map_err(|error| {
        PkiError::ParseFailed(format!("{}: {error}", server_key_path.display()))
    })?;
    let mut roots = RootCertStore::empty();
    let root_certificate = root_certificates.into_iter().next().ok_or_else(|| {
        PkiError::ValidationFailed(format!("{} has no trust anchor", root_ca_path.display()))
    })?;
    roots.add(root_certificate).map_err(|error| {
        PkiError::ValidationFailed(format!("{}: {error}", root_ca_path.display()))
    })?;

    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|error| PkiError::ValidationFailed(format!("verifier setup: {error}")))?;
    let server_name = ServerName::try_from(server_hostname)
        .map_err(|_| PkiError::ValidationFailed("invalid server hostname".to_string()))?
        .to_owned();
    verifier
        .verify_server_cert(
            &server_chain[0],
            &server_chain[1..],
            &server_name,
            &[],
            validation_time,
        )
        .map_err(|error| PkiError::ValidationFailed(format!("server chain: {error}")))?;

    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| PkiError::ValidationFailed(format!("TLS versions: {error}")))?
        .with_no_client_auth()
        .with_single_cert(server_chain, private_key)
        .map_err(|error| {
            PkiError::ValidationFailed(format!("server key does not match certificate: {error}"))
        })?;

    Ok(())
}

fn quarantine_existing_pki(
    pki_dir: &Path,
    paths: &[&Path],
    pki_time: PkiTime,
) -> Result<std::path::PathBuf, PkiError> {
    let stamp = pki_time.quarantine_stamp();
    let quarantine_dir = pki_dir.join(format!(".invalid-pki-{stamp}-{}", std::process::id()));
    if path_exists_no_follow(&quarantine_dir) {
        return Err(PkiError::IoError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("quarantine path already exists: {}", quarantine_dir.display()),
        )));
    }
    std::fs::create_dir(&quarantine_dir)?;
    for path in paths.iter().copied().filter(|path| path_exists_no_follow(path)) {
        let file_name = path.file_name().ok_or_else(|| {
            PkiError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid PKI path: {}", path.display()),
            ))
        })?;
        std::fs::rename(path, quarantine_dir.join(file_name))?;
    }
    Ok(quarantine_dir)
}

/// Convert DER bytes to PEM format.
fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::fmt::Write;
    let b64 = STANDARD.encode(der);
    let mut pem = String::new();
    let _ = writeln!(pem, "-----BEGIN {label}-----");
    for chunk in b64.as_bytes().chunks(64) {
        // base64 output is always valid ASCII/UTF-8.
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    let _ = writeln!(pem, "-----END {label}-----");
    pem
}

/// Initialize a production PKI at the given directory. Generates the full
/// hierarchy if the root CA doesn't exist yet. Returns the paths to the
/// server leaf cert chain and key.
pub fn ensure_pki(
    pki_dir: &Path,
    server_hostname: &str,
    organization: &str,
) -> Result<(std::path::PathBuf, std::path::PathBuf), PkiError> {
    let pki_time = PkiTime::capture()?;
    ensure_pki_at(pki_dir, server_hostname, organization, pki_time)
}

fn ensure_pki_at(
    pki_dir: &Path,
    server_hostname: &str,
    organization: &str,
    pki_time: PkiTime,
) -> Result<(std::path::PathBuf, std::path::PathBuf), PkiError> {
    let root_ca_path = pki_dir.join("ca-root.crt");
    let intermediate_ca_path = pki_dir.join("ca-intermediate.crt");
    let server_cert_path = pki_dir.join("server.crt");
    let server_key_path = pki_dir.join("server.key");

    let pki_paths: [&Path; 4] = [
        root_ca_path.as_path(),
        intermediate_ca_path.as_path(),
        server_cert_path.as_path(),
        server_key_path.as_path(),
    ];
    // Existing material is reusable only after parsing, key matching, hostname,
    // expiry, and full chain validation against the local root CA.
    if path_exists_no_follow(&server_cert_path) && path_exists_no_follow(&server_key_path) {
        match validate_existing_pki_at(pki_dir, server_hostname, pki_time) {
            Ok(()) => {
                log::info!(
                    "PKI: Using existing validated server certificate at {}",
                    server_cert_path.display()
                );
                return Ok((server_cert_path, server_key_path));
            }
            Err(error) => {
                log::warn!(
                    "PKI: Existing material is invalid; preserving it before regeneration: {error}"
                );
            }
        }
    }

    if pki_paths.iter().any(|path| path_exists_no_follow(path)) {
        let quarantine_dir = quarantine_existing_pki(pki_dir, &pki_paths, pki_time)?;
        log::warn!("PKI: Moved invalid or incomplete material to {}", quarantine_dir.display());
    }

    log::info!(
        "PKI: Generating new CA hierarchy in {} for hostname '{}'",
        pki_dir.display(),
        server_hostname
    );

    #[cfg(feature = "rcgen")]
    let mut hierarchy = generate_hierarchy_at(server_hostname, organization, pki_time)?;
    #[cfg(not(feature = "rcgen"))]
    let mut hierarchy = generate_hierarchy(server_hostname, organization)?;

    // Write root CA.
    write_ca_cert_pem(&hierarchy.root_ca.cert_der, &root_ca_path)?;
    // Write intermediate CA.
    write_ca_cert_pem(&hierarchy.intermediate_ca.cert_der, &intermediate_ca_path)?;
    // Write server leaf + intermediate as chain (full chain for clients).
    write_cert_chain_pem(
        &hierarchy.server_leaf.cert_der,
        &hierarchy.intermediate_ca.cert_der,
        &server_cert_path,
    )?;
    // Write server key separately (does not overwrite the cert chain).
    write_key_pem(&mut hierarchy.server_leaf.key_der, &server_key_path)?;

    log::info!("PKI: Hierarchy generated successfully");
    Ok((server_cert_path, server_key_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(name: &str) -> std::path::PathBuf {
        static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let sequence = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("qf_pki-{name}-{}-{sequence}", std::process::id()))
    }

    /// A directory that exists for the duration of one test and is removed after.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = test_directory(name);
            std::fs::create_dir_all(&path).expect("scratch directory");
            Self(path)
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn pki_writes_replace_existing_material_and_leave_no_staging_file() {
        let scratch = Scratch::new("write-replace");
        let target = scratch.join("ca-root.crt");

        write_ca_cert_pem(b"first", &target).expect("initial write");
        assert_eq!(
            std::fs::read_to_string(&target).expect("first read"),
            der_to_pem(b"first", "CERTIFICATE")
        );
        write_ca_cert_pem(b"second", &target).expect("replacing write");

        let replaced = std::fs::read_to_string(&target).expect("second read");
        assert!(replaced.contains("BEGIN CERTIFICATE"), "content must be the new PEM");
        assert_ne!(replaced, der_to_pem(b"first", "CERTIFICATE"), "content must be replaced");
        assert_eq!(replaced, der_to_pem(b"second", "CERTIFICATE"));

        let leftovers: Vec<_> = std::fs::read_dir(&scratch.0)
            .expect("scratch listing")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "staging files must not survive: {leftovers:?}");
    }

    #[test]
    fn pki_writers_reject_a_symlinked_target_without_touching_its_destination() {
        #[cfg(unix)]
        {
            let scratch = Scratch::new("symlink-reject");
            let victim = scratch.join("victim");
            std::fs::write(&victim, b"untouched").expect("victim file");

            for name in ["server.key", "server.crt", "ca-root.crt"] {
                let link = scratch.join(name);
                std::os::unix::fs::symlink(&victim, &link).expect("symlink");

                let mut key = b"key material".to_vec();
                let key_error =
                    write_key_pem(&mut key, &link).expect_err("key writer must reject a symlink");
                let chain_error = write_cert_chain_pem(b"leaf", b"inter", &link)
                    .expect_err("chain writer must reject a symlink");
                let ca_error =
                    write_ca_cert_pem(b"ca", &link).expect_err("CA writer must reject a symlink");

                for error in [key_error, chain_error, ca_error] {
                    match error {
                        PkiError::UnsafePath(message) => assert!(
                            message.contains("symlink"),
                            "{name} rejection must name the defect, got {message}"
                        ),
                        other => panic!("{name} must be rejected as an unsafe path, got {other}"),
                    }
                }

                assert_eq!(
                    std::fs::read(&victim).expect("victim survives"),
                    b"untouched",
                    "{name} must not write through the link"
                );
                assert!(
                    std::fs::symlink_metadata(&link)
                        .expect("link survives")
                        .file_type()
                        .is_symlink(),
                    "{name} must be left as it was found"
                );
                std::fs::remove_file(&link).expect("cleanup link");
            }
        }
    }

    #[test]
    fn private_keys_are_created_unreadable_to_other_accounts() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let scratch = Scratch::new("key-mode");
            let key_path = scratch.join("server.key");
            let mut key = b"key material".to_vec();

            write_key_pem(&mut key, &key_path).expect("key write");

            let mode = std::fs::metadata(&key_path).expect("key metadata").permissions().mode();
            assert_eq!(mode & 0o777, PKI_KEY_MODE, "private key mode must be 0600");
            assert!(key.iter().all(|byte| *byte == 0), "the caller's DER must be zeroized");

            // Replacement must not widen the mode either: the staging file carries it,
            // so a pre-existing permissive file cannot survive the rename.
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o666))
                .expect("widen mode");
            let mut second = b"key material".to_vec();
            write_key_pem(&mut second, &key_path).expect("replacing key write");
            let mode = std::fs::metadata(&key_path).expect("key metadata").permissions().mode();
            assert_eq!(mode & 0o777, PKI_KEY_MODE, "replacement must not inherit a wider mode");
        }
    }

    #[test]
    fn a_dangling_symlink_is_seen_as_present_and_is_still_rejected() {
        #[cfg(unix)]
        {
            // `Path::exists()` resolves the link and reports absent here, which is how a
            // planted link would otherwise slip past an existence check and then be
            // written through.
            let scratch = Scratch::new("dangling");
            let link = scratch.join("server.crt");
            std::os::unix::fs::symlink(scratch.join("nowhere"), &link).expect("dangling symlink");

            assert!(!link.exists(), "the resolving check is the one that is wrong here");
            assert!(path_exists_no_follow(&link), "the link occupies the name");
            assert!(matches!(write_ca_cert_pem(b"ca", &link), Err(PkiError::UnsafePath(_))));
            assert!(!scratch.join("nowhere").exists(), "the link target must not be created");
        }
    }

    #[test]
    fn a_missing_parent_directory_is_reported_and_nothing_is_created() {
        let scratch = Scratch::new("missing-parent");
        let target = scratch.join("absent").join("ca-root.crt");
        let error = write_ca_cert_pem(b"ca", &target).expect_err("a missing parent must fail");
        assert!(
            matches!(error, PkiError::IoError(ref io) if io.kind() == std::io::ErrorKind::NotFound),
            "expected a not-found parent, got {error}"
        );
        assert!(!scratch.join("absent").exists(), "no directory may be created implicitly");
    }

    #[test]
    fn test_der_to_pem() {
        let der = b"Hello, World!";
        let pem = der_to_pem(der, "TEST");
        assert!(pem.starts_with("-----BEGIN TEST-----"));
        assert!(pem.ends_with("-----END TEST-----\n"));
    }

    #[test]
    fn test_der_to_pem_uses_standard_base64_padding() {
        assert!(der_to_pem(b"", "TEST").contains("-----BEGIN TEST-----\n-----END TEST-----"));
        assert!(der_to_pem(b"f", "TEST").contains("Zg==\n"));
        assert!(der_to_pem(b"fo", "TEST").contains("Zm8=\n"));
        assert!(der_to_pem(b"foo", "TEST").contains("Zm9v\n"));
        assert!(der_to_pem(b"foobar", "TEST").contains("Zm9vYmFy\n"));
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_generate_hierarchy() {
        let hierarchy = generate_hierarchy("vpn.example.com", "TestOrg").unwrap();
        // All certs should have non-empty DER.
        assert!(!hierarchy.root_ca.cert_der.is_empty());
        assert!(!hierarchy.root_ca.key_der.is_empty());
        assert!(!hierarchy.intermediate_ca.cert_der.is_empty());
        assert!(!hierarchy.intermediate_ca.key_der.is_empty());
        assert!(!hierarchy.server_leaf.cert_der.is_empty());
        assert!(!hierarchy.server_leaf.key_der.is_empty());
        // Root and intermediate DERs should differ.
        assert_ne!(hierarchy.root_ca.cert_der, hierarchy.intermediate_ca.cert_der);
        assert_ne!(hierarchy.intermediate_ca.cert_der, hierarchy.server_leaf.cert_der);
    }

    #[test]
    fn test_pki_time_rejects_pre_epoch_clock() {
        let error = PkiTime::from_system_time(UNIX_EPOCH - Duration::from_secs(1))
            .expect_err("pre-epoch time must be rejected");
        assert!(matches!(error, PkiError::ClockError(_)));
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_checked_validity_window_enforces_order_and_boundaries() {
        let not_before = time::OffsetDateTime::UNIX_EPOCH;
        let validity = checked_validity_window(not_before, time::Duration::days(1), "test")
            .expect("positive validity must be accepted");
        assert_eq!(validity.not_before, not_before);
        assert_eq!(validity.not_after, not_before + time::Duration::days(1));
        assert!(validity.not_before < validity.not_after);

        let error = checked_validity_window(not_before, time::Duration::ZERO, "test")
            .expect_err("zero-length validity must be rejected");
        assert!(matches!(error, PkiError::InvalidValidity(_)));
    }

    #[cfg(feature = "rcgen")]
    struct CountingPkiClock {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        system_now: SystemTime,
    }

    #[cfg(feature = "rcgen")]
    impl PkiClock for CountingPkiClock {
        fn now_system(&self) -> SystemTime {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.system_now
        }
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_generate_hierarchy_captures_one_checked_instant() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let clock = CountingPkiClock {
            calls: calls.clone(),
            system_now: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        };

        let pki_time = PkiTime::capture_from(&clock).unwrap();
        let hierarchy = generate_hierarchy_at("vpn.example.com", "TestOrg", pki_time).unwrap();
        assert!(!hierarchy.server_leaf.cert_der.is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_generate_hierarchy_propagates_checked_clock_failure() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let clock = CountingPkiClock {
            calls: calls.clone(),
            system_now: UNIX_EPOCH - Duration::from_secs(1),
        };

        let result = PkiTime::capture_from(&clock)
            .and_then(|pki_time| generate_hierarchy_at("vpn.example.com", "TestOrg", pki_time));
        assert!(matches!(result, Err(PkiError::ClockError(_))));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_generate_hierarchy_accepts_unix_epoch_boundary() {
        let pki_time = PkiTime::from_system_time(UNIX_EPOCH).unwrap();
        let hierarchy = generate_hierarchy_at("vpn.example.com", "TestOrg", pki_time)
            .expect("Unix epoch is a representable certificate boundary");
        assert!(!hierarchy.root_ca.cert_der.is_empty());
        assert!(!hierarchy.intermediate_ca.cert_der.is_empty());
        assert!(!hierarchy.server_leaf.cert_der.is_empty());
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_ensure_pki_chain_contains_leaf_and_intermediate() {
        let dir = test_directory("chain");
        std::fs::create_dir_all(&dir).unwrap();

        let (cert_path, key_path) = ensure_pki(&dir, "vpn.example.com", "TestOrg").unwrap();

        // The cert file must contain BOTH the leaf and the intermediate
        // (two "BEGIN CERTIFICATE" blocks), not just the leaf.
        let cert_content = std::fs::read_to_string(&cert_path).unwrap();
        let cert_count = cert_content.matches("BEGIN CERTIFICATE").count();
        assert_eq!(
            cert_count, 2,
            "server.crt must contain leaf + intermediate chain, found {cert_count} cert(s)"
        );

        // The key file must contain a private key, not a certificate.
        let key_content = std::fs::read_to_string(&key_path).unwrap();
        assert!(key_content.contains("BEGIN PRIVATE KEY"), "server.key must contain a private key");
        assert!(
            !key_content.contains("BEGIN CERTIFICATE"),
            "server.key must NOT contain a certificate"
        );

        // Key file must have 0600 permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(
                perms & 0o777,
                0o600,
                "server.key must have 0600 permissions, got {:o}",
                perms & 0o777
            );
        }

        // Calling ensure_pki again should reuse existing certs (idempotent).
        let (cert2, key2) = ensure_pki(&dir, "vpn.example.com", "TestOrg").unwrap();
        assert_eq!(cert_path, cert2);
        assert_eq!(key_path, key2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "rcgen")]
    fn write_expired_hierarchy(dir: &Path) {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose, SanType,
        };

        let now = PkiTime::from_system_time(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
            .unwrap()
            .offset_datetime()
            .unwrap();

        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.distinguished_name = DistinguishedName::new();
        root_params.distinguished_name.push(DnType::OrganizationName, "TestOrg");
        root_params.distinguished_name.push(DnType::CommonName, "TestOrg Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root_params.not_before = now - time::Duration::days(2);
        root_params.not_after = now + time::Duration::days(365);
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let mut intermediate_params = CertificateParams::new(vec![]).unwrap();
        intermediate_params.distinguished_name = DistinguishedName::new();
        intermediate_params.distinguished_name.push(DnType::OrganizationName, "TestOrg");
        intermediate_params.distinguished_name.push(DnType::CommonName, "TestOrg Intermediate CA");
        intermediate_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        intermediate_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        intermediate_params.not_before = now - time::Duration::days(2);
        intermediate_params.not_after = now + time::Duration::days(365);
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate_cert =
            intermediate_params.signed_by(&intermediate_key, &root_cert, &root_key).unwrap();

        let mut leaf_params = CertificateParams::new(vec![]).unwrap();
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params.distinguished_name.push(DnType::OrganizationName, "TestOrg");
        leaf_params.distinguished_name.push(DnType::CommonName, "vpn.example.com");
        leaf_params.subject_alt_names =
            vec![SanType::DnsName(rcgen::Ia5String::try_from("vpn.example.com").unwrap())];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.not_before = now - time::Duration::days(2);
        leaf_params.not_after = now - time::Duration::days(1);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert =
            leaf_params.signed_by(&leaf_key, &intermediate_cert, &intermediate_key).unwrap();

        write_ca_cert_pem(root_cert.der(), &dir.join("ca-root.crt")).unwrap();
        write_ca_cert_pem(intermediate_cert.der(), &dir.join("ca-intermediate.crt")).unwrap();
        write_cert_chain_pem(leaf_cert.der(), intermediate_cert.der(), &dir.join("server.crt"))
            .unwrap();
        let mut key_der = leaf_key.serialize_der();
        write_key_pem(&mut key_der, &dir.join("server.key")).unwrap();
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_ensure_pki_regenerates_corrupted_existing_certificate() {
        let pki_time =
            PkiTime::from_system_time(UNIX_EPOCH + Duration::from_secs(1_800_000_000)).unwrap();
        let dir = test_directory("corrupt");
        std::fs::create_dir_all(&dir).unwrap();

        let (cert_path, _) = ensure_pki_at(&dir, "vpn.example.com", "TestOrg", pki_time).unwrap();
        std::fs::write(&cert_path, b"corrupted certificate").unwrap();

        ensure_pki_at(&dir, "vpn.example.com", "TestOrg", pki_time).unwrap();

        let certificates =
            parse_certificates(&std::fs::read(&cert_path).unwrap(), &cert_path).unwrap();
        assert_eq!(certificates.len(), 2);
        validate_existing_pki_at(&dir, "vpn.example.com", pki_time).unwrap();
        assert!(std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(".invalid-pki-")));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_ensure_pki_regenerates_expired_certificate() {
        let pki_time =
            PkiTime::from_system_time(UNIX_EPOCH + Duration::from_secs(1_800_000_000)).unwrap();
        let dir = test_directory("expired");
        std::fs::create_dir_all(&dir).unwrap();
        write_expired_hierarchy(&dir);
        let expired_certificate = std::fs::read(dir.join("server.crt")).unwrap();

        ensure_pki_at(&dir, "vpn.example.com", "TestOrg", pki_time).unwrap();

        let regenerated_certificate = std::fs::read(dir.join("server.crt")).unwrap();
        assert_ne!(regenerated_certificate, expired_certificate);
        validate_existing_pki_at(&dir, "vpn.example.com", pki_time).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_pki_error_display() {
        let e = PkiError::GenerationFailed("test".into());
        assert!(format!("{e}").contains("test"));
        let e = PkiError::FeatureNotEnabled;
        assert!(format!("{e}").contains("not enabled"));
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_generated_cert_drop_runs_without_panic() {
        // Smoke test: dropping a GeneratedCert (which zeroizes key_der in its
        // Drop impl) must not panic. The zeroize crate's volatile-write
        // contract guarantees the buffer is scrubbed before the Vec's
        // allocator frees it; a reliable post-free memory inspection is not
        // possible in safe Rust, so we verify the zeroize primitive itself
        // in test_zeroize_scrubs_key_der below.
        let cert = generate_hierarchy("vpn.example.com", "TestOrg").unwrap();
        assert!(!cert.root_ca.key_der.is_empty());
        drop(cert); // Must not panic.
    }

    #[test]
    fn test_zeroize_scrubs_key_der() {
        // Directly verify that zeroize on a key_der Vec scrubs the key
        // material. The `zeroize` crate's Vec<T: Zeroize> impl zeroizes
        // each element and then truncates the Vec to length 0, so the
        // bytes are no longer observable through the Vec. This is the
        // primitive the GeneratedCert::drop impl relies on.
        use zeroize::Zeroize;
        let mut key = vec![0xABu8; 64];
        assert!(key.iter().any(|&b| b != 0), "key must be non-zero before zeroize");
        key.zeroize();
        assert_eq!(key.len(), 0, "zeroize must clear the Vec so bytes are unobservable");
    }
}
