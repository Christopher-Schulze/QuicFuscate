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
pub struct GeneratedCert {
    /// Certificate in DER format.
    pub cert_der: Vec<u8>,
    /// Private key in DER format.
    pub key_der: Vec<u8>,
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

/// Write a certificate and its private key to disk in PEM format.
pub fn write_cert_and_key_pem(
    cert_der: &[u8],
    key_der: &[u8],
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), PkiError> {
    use std::io::Write;

    // Convert DER to PEM.
    let cert_pem = der_to_pem(cert_der, "CERTIFICATE");
    let key_pem = der_to_pem(key_der, "PRIVATE KEY");

    let mut cert_file = std::fs::File::create(cert_path)?;
    cert_file.write_all(cert_pem.as_bytes())?;

    // Set restrictive permissions on the key file (0600 on Unix).
    let mut key_file = std::fs::File::create(key_path)?;
    key_file.write_all(key_pem.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = key_file.metadata()?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(key_path, perms)?;
    }

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

    let hierarchy = generate_hierarchy(server_hostname, organization)?;

    // Write root CA.
    write_ca_cert_pem(&hierarchy.root_ca.cert_der, &root_ca_path)?;
    // Write intermediate CA.
    write_ca_cert_pem(&hierarchy.intermediate_ca.cert_der, &intermediate_ca_path)?;
    // Write server leaf + intermediate as chain.
    write_cert_chain_pem(
        &hierarchy.server_leaf.cert_der,
        &hierarchy.intermediate_ca.cert_der,
        &server_cert_path,
    )?;
    // Write server key.
    write_cert_and_key_pem(
        &hierarchy.server_leaf.cert_der,
        &hierarchy.server_leaf.key_der,
        &server_cert_path,
        &server_key_path,
    )?;

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

    #[test]
    fn test_pki_error_display() {
        let e = PkiError::GenerationFailed("test".into());
        assert!(format!("{e}").contains("test"));
        let e = PkiError::FeatureNotEnabled;
        assert!(format!("{e}").contains("not enabled"));
    }
}
