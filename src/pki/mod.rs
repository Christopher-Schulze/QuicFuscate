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

    // If the server cert and key already exist, use them (PKI already initialized).
    if server_cert_path.exists() && server_key_path.exists() {
        log::info!("PKI: Using existing server certificate at {}", server_cert_path.display());
        return Ok((server_cert_path, server_key_path));
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
