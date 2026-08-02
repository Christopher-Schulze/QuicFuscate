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

/// Error type for PKI operations.
#[derive(Debug)]
pub enum PkiError {
    /// Certificate generation failed.
    GenerationFailed(String),
    /// Certificate parsing failed.
    ParseFailed(String),
    /// Chain validation failed.
    ValidationFailed(String),
    /// I/O error.
    IoError(std::io::Error),
    /// Feature not enabled (rcgen not compiled).
    FeatureNotEnabled,
}

impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenerationFailed(s) => write!(f, "cert generation failed: {s}"),
            Self::ParseFailed(s) => write!(f, "cert parse failed: {s}"),
            Self::ValidationFailed(s) => write!(f, "chain validation failed: {s}"),
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
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyUsagePurpose, SanType,
    };

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
    root_params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(ROOT_CA_VALIDITY_DAYS as i64);
    root_params.not_before = time::OffsetDateTime::now_utc();
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
    inter_params.not_after = time::OffsetDateTime::now_utc()
        + time::Duration::days(INTERMEDIATE_CA_VALIDITY_DAYS as i64);
    inter_params.not_before = time::OffsetDateTime::now_utc();
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
    leaf_params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(SERVER_LEAF_VALIDITY_DAYS as i64);
    leaf_params.not_before = time::OffsetDateTime::now_utc();
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

/// Generate a full CA hierarchy (stub when rcgen is not enabled).
#[cfg(not(feature = "rcgen"))]
pub fn generate_hierarchy(
    _server_hostname: &str,
    _organization: &str,
) -> Result<CaHierarchy, PkiError> {
    Err(PkiError::FeatureNotEnabled)
}

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
    use std::io::Write;
    use zeroize::Zeroize;

    // Zeroizing<String> guarantees the PEM-encoded key material is scrubbed
    // via volatile writes on drop, regardless of which `?` early-returns.
    let key_pem = zeroize::Zeroizing::new(der_to_pem(key_der, "PRIVATE KEY"));

    // On Unix, open the file with mode 0600 atomically via OpenOptions::mode
    // so the private key is never briefly world-readable on disk. This
    // eliminates the TOCTOU window that File::create (default 0644) +
    // post-hoc set_permissions would leave.
    #[cfg(unix)]
    let mut key_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(key_path)?
    };
    #[cfg(not(unix))]
    let mut key_file = std::fs::File::create(key_path)?;

    key_file.write_all(key_pem.as_bytes())?;
    key_file.sync_all()?;

    // Zeroize the caller's key_der slice on the success path. On early
    // return, GeneratedCert::drop (if the caller owns one) still scrubs it.
    key_der.zeroize();

    Ok(())
}

/// Write a certificate chain (leaf + intermediate) to a single PEM file.
pub fn write_cert_chain_pem(
    leaf_der: &[u8],
    intermediate_der: &[u8],
    chain_path: &Path,
) -> Result<(), PkiError> {
    use std::io::Write;
    let leaf_pem = der_to_pem(leaf_der, "CERTIFICATE");
    let inter_pem = der_to_pem(intermediate_der, "CERTIFICATE");
    let mut file = std::fs::File::create(chain_path)?;
    file.write_all(leaf_pem.as_bytes())?;
    file.write_all(inter_pem.as_bytes())?;
    Ok(())
}

/// Write a CA certificate to disk in PEM format.
pub fn write_ca_cert_pem(ca_der: &[u8], ca_path: &Path) -> Result<(), PkiError> {
    use std::io::Write;
    let pem = der_to_pem(ca_der, "CERTIFICATE");
    let mut file = std::fs::File::create(ca_path)?;
    file.write_all(pem.as_bytes())?;
    Ok(())
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

fn validate_existing_pki(pki_dir: &Path, server_hostname: &str) -> Result<(), PkiError> {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer, ServerName, UnixTime};
    use rustls::RootCertStore;
    use std::sync::Arc;

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
            UnixTime::now(),
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
) -> Result<std::path::PathBuf, PkiError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|error| {
            PkiError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("system clock predates Unix epoch: {error}"),
            ))
        })?;
    let quarantine_dir = pki_dir.join(format!(".invalid-pki-{stamp}-{}", std::process::id()));
    if quarantine_dir.exists() {
        return Err(PkiError::IoError(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("quarantine path already exists: {}", quarantine_dir.display()),
        )));
    }
    std::fs::create_dir(&quarantine_dir)?;
    for path in paths.iter().copied().filter(|path| path.exists()) {
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
    use std::fmt::Write;
    let b64 = base64_encode(der);
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

/// Base64 encoder (no external dependency).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = chunk;
        let n = ((b[0] as u32) << 16)
            | ((b.get(1).copied().unwrap_or(0) as u32) << 8)
            | (b.get(2).copied().unwrap_or(0) as u32);
        result.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        if b.len() > 1 {
            result.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if b.len() > 2 {
            result.push(TABLE[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Initialize a production PKI at the given directory. Generates the full
/// hierarchy if the root CA doesn't exist yet. Returns the paths to the
/// server leaf cert chain and key.
pub fn ensure_pki(
    pki_dir: &Path,
    server_hostname: &str,
    organization: &str,
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
    if server_cert_path.exists() && server_key_path.exists() {
        match validate_existing_pki(pki_dir, server_hostname) {
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

    if pki_paths.iter().any(|path| path.exists()) {
        let quarantine_dir = quarantine_existing_pki(pki_dir, &pki_paths)?;
        log::warn!("PKI: Moved invalid or incomplete material to {}", quarantine_dir.display());
    }

    log::info!(
        "PKI: Generating new CA hierarchy in {} for hostname '{}'",
        pki_dir.display(),
        server_hostname
    );

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

    #[test]
    fn test_der_to_pem() {
        let der = b"Hello, World!";
        let pem = der_to_pem(der, "TEST");
        assert!(pem.starts_with("-----BEGIN TEST-----"));
        assert!(pem.ends_with("-----END TEST-----\n"));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
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

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_ensure_pki_chain_contains_leaf_and_intermediate() {
        let dir = std::env::temp_dir().join(format!(
            "qf_pki_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
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

        let now = time::OffsetDateTime::now_utc();

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
        let dir = std::env::temp_dir().join(format!(
            "qf_pki_corrupt_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let (cert_path, _) = ensure_pki(&dir, "vpn.example.com", "TestOrg").unwrap();
        std::fs::write(&cert_path, b"corrupted certificate").unwrap();

        ensure_pki(&dir, "vpn.example.com", "TestOrg").unwrap();

        let certificates =
            parse_certificates(&std::fs::read(&cert_path).unwrap(), &cert_path).unwrap();
        assert_eq!(certificates.len(), 2);
        validate_existing_pki(&dir, "vpn.example.com").unwrap();
        assert!(std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(".invalid-pki-")));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "rcgen")]
    #[test]
    fn test_ensure_pki_regenerates_expired_certificate() {
        let dir = std::env::temp_dir().join(format!(
            "qf_pki_expired_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        write_expired_hierarchy(&dir);
        let expired_certificate = std::fs::read(dir.join("server.crt")).unwrap();

        ensure_pki(&dir, "vpn.example.com", "TestOrg").unwrap();

        let regenerated_certificate = std::fs::read(dir.join("server.crt")).unwrap();
        assert_ne!(regenerated_certificate, expired_certificate);
        validate_existing_pki(&dir, "vpn.example.com").unwrap();

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
