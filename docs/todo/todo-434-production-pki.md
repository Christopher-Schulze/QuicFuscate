---
id: TODO-434
title: Production PKI — CA hierarchy, cert generation CLI, cert pinning, remove self-signed fallback
severity: CRITICAL
phase: "G"
priority: P0
status: OPEN
created: 2026-06-30
depends_on: []
---

# TODO-434: Production PKI

## Problem

The QuicFuscate TLS infrastructure has no production-grade PKI. The server falls back to
ephemeral self-signed certificates when no cert/key files are found, there is no CA
hierarchy, no OCSP, no CRL, no cert pinning, and no cert rotation. This is a critical
security blocker for production deployment.

### Code Evidence

**1. Ephemeral self-signed fallback** (`src/qftls.rs:1246-1307`):

`create_server_connection()` (line 1228) attempts to load cert/key from file. If loading
fails and `TLS_OVERRIDE_REQUIRED` is false, it falls back to
`generate_ephemeral_self_signed()` (line 1249):

```rust
log::warn!(
    "No TLS cert/key found on disk. Generating ephemeral self-signed cert (development default)."
);
Self::generate_ephemeral_self_signed()?
```

`generate_ephemeral_self_signed()` (line 1279-1307) creates a self-signed cert with:
- CN = "localhost"
- SAN = localhost, 127.0.0.1, ::1
- No CA signing
- No chain
- Ephemeral key generated at startup, lost on restart

This means any production server that starts without cert files silently runs with a
self-signed cert that clients cannot verify (unless they disable verification). The warning
is logged but not fatal — an operator could easily miss it.

**2. No CA hierarchy:**

- `config/local/` contains only `.gitkeep` (plus `admin-auth.json`, `admin-local.toml`,
  dev certs). No CA cert, no intermediate CA, no cert chain.
- `config/local/dev-certs/` has ad-hoc admin certs (`admin-local-*.crt`) but no server
  CA hierarchy.
- `load_certs_from_file()` (line 1309) searches `certs/server.crt`,
  `/etc/quicfuscate/server.crt`, `server.crt` — but there is no tooling to generate these
  files with a proper CA chain.

**3. No OCSP / CRL:**

A grep for `OCSP|CRL` in `src/qftls.rs` returns matches only in the `ServerCertVerifier`
trait signatures (line 949: `_ocsp_response: &[u8]`) — the parameter is ignored. There is
no OCSP stapling, no CRL distribution point, no revocation checking.

**4. No cert pinning:**

The client validates against CA roots (native + webpki + `--ca-file` override, line 1150).
There is no mechanism to pin a specific server cert fingerprint. If an attacker obtains a
valid cert from a trusted CA (e.g., via a compromised CA), they can MITM the connection.
Cert pinning (comparing the server cert's SHA-256 fingerprint to a known-good value) is
the standard defense.

**5. No cert rotation:**

Certs are loaded once at startup. There is no mechanism to reload certs without restarting
the server. For production, certs should be rotatable with zero downtime (SIGHUP triggers
reload, or a file-watcher).

**6. No cert expiration checking:**

`load_certs_from_file()` (line 1309) loads certs without checking their validity period.
An expired cert is loaded silently and will cause TLS handshake failures only when a client
connects. The server should check cert expiration on load and log a warning if expiration
is within 30 days.

**7. No cert generation CLI:**

`quicfuscate-ctl` (`src/bin/quicfuscate-ctl.rs`) supports `status`, `clients`, `kick`,
`block`, `unblock`, `reload`, `qkey`, `shutdown` — but no `cert` subcommand. There is no
way to generate a CA, sign a server cert, or inspect cert chains from the CLI.

## Goal

A complete production PKI:

1. **Root CA + Intermediate CA** generation via `quicfuscate-ctl cert generate-ca`.
2. **Server cert** signed by the CA via `quicfuscate-ctl cert generate-server`.
3. **Cert chain** (server cert + intermediate CA) sent during TLS handshake.
4. **Cert expiration** checking on load with 30-day warning.
5. **Cert pinning** — client pins server cert fingerprint, verified on connect.
6. **Cert rotation** — SIGHUP triggers cert reload without restart.
7. **Remove self-signed fallback** in release builds (only allowed in `dev-certs` feature).

## Implementation Plan

### Step 1: Create PKI module

Create `src/pki.rs` (or `src/pki/mod.rs`):

```rust
//! Production PKI: CA generation, server cert signing, cert chain management.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;

/// CA certificate parameters
pub struct CaParams {
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub validity_days: u32,  // e.g., 3650 for root CA (10 years)
}

/// Server certificate parameters
pub struct ServerCertParams {
    pub common_name: String,
    pub san_dns: Vec<String>,
    pub san_ips: Vec<std::net::IpAddr>,
    pub validity_days: u32,  // e.g., 365 for server cert (1 year)
}

/// Generate a root CA certificate and private key.
pub fn generate_root_ca(params: &CaParams) -> Result<(Vec<u8>, Vec<u8>), PkiError> {
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CountryName, &params.country);
    ca_params.distinguished_name.push(DnType::OrganizationName, &params.organization);
    ca_params.distinguished_name.push(DnType::CommonName, &params.common_name);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::OrganizationalUnitName, "QuicFuscate Root CA");
    // Key usage: keyCertSign, cRLSign
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    // Validity
    ca_params.not_before = time::OffsetDateTime::now_utc();
    ca_params.not_after = ca_params.not_before + time::Duration::days(params.validity_days as i64);

    let key_pair = KeyPair::generate()?;
    let cert = ca_params.self_signed(&key_pair)?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

/// Generate an intermediate CA signed by the root CA.
pub fn generate_intermediate_ca(
    params: &CaParams,
    root_ca_cert: &[u8],
    root_ca_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), PkiError> { ... }

/// Generate a server certificate signed by the intermediate CA.
pub fn generate_server_cert(
    params: &ServerCertParams,
    intermediate_ca_cert: &[u8],
    intermediate_ca_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), PkiError> {
    let mut cert_params = CertificateParams::default();
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params.distinguished_name.push(DnType::CommonName, &params.common_name);
    cert_params.distinguished_name.push(DnType::OrganizationName, "QuicFuscate");

    // SANs
    cert_params.subject_alt_names = params.san_dns.iter().map(|d| {
        SanType::DnsName(rcgen::Ia5String::try_from(d.as_str()).unwrap())
    }).chain(params.san_ips.iter().map(|ip| SanType::IpAddress(*ip)))
    .collect();

    // Extended Key Usage: serverAuth
    cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    // Validity
    cert_params.not_before = time::OffsetDateTime::now_utc();
    cert_params.not_after = cert_params.not_before + time::Duration::days(params.validity_days as i64);

    // Sign with intermediate CA
    let root_key = KeyPair::from_der(intermediate_ca_key)?;
    let root_cert = rcgen::Certificate::from_params(cert_params)?;
    let signed = root_cert.serialize_der_with_signer(&root_key)?;

    Ok((signed, root_key.serialize_der()))
}

/// Compute SHA-256 fingerprint of a certificate (for pinning).
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(cert_der);
    hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

/// Check if a certificate is expired or will expire within `warn_days`.
pub fn check_cert_expiration(
    cert_der: &[u8],
    warn_days: u32,
) -> Result<CertExpiry, PkiError> { ... }
```

### Step 2: Add cert subcommand to quicfuscate-ctl

Extend `src/bin/quicfuscate-ctl.rs` with cert management commands. These are **local**
operations (not sent to the server via Unix socket) — they generate files on disk:

```rust
// In main():
"cert" => {
    if args.len() < 3 {
        eprintln!("Usage: quicfuscate-ctl cert <subcommand> [options]");
        eprintln!("Subcommands:");
        eprintln!("  generate-ca [--org NAME] [--country CC] [--out-dir DIR]");
        eprintln!("  generate-server --cn NAME [--san DNS] [--san-ip IP] [--ca-dir DIR] [--out-dir DIR]");
        eprintln!("  inspect --cert PATH");
        eprintln!("  fingerprint --cert PATH");
        std::process::exit(1);
    }
    match args[2].as_str() {
        "generate-ca" => cert_generate_ca(&args[3..]),
        "generate-server" => cert_generate_server(&args[3..]),
        "inspect" => cert_inspect(&args[3..]),
        "fingerprint" => cert_fingerprint_cmd(&args[3..]),
        _ => { eprintln!("Unknown cert subcommand: {}", args[2]); std::process::exit(1); }
    }
}
```

`cert_generate_ca`:
- Generates root CA (10-year validity) → `ca-root.crt` + `ca-root.key`
- Generates intermediate CA (5-year validity) signed by root → `ca-intermediate.crt` + `ca-intermediate.key`
- Outputs to `--out-dir` (default: `config/local/pki/`)
- Prints the root CA fingerprint for client pinning

`cert_generate_server`:
- Loads intermediate CA from `--ca-dir`
- Generates server cert (1-year validity) signed by intermediate CA
- Outputs `server.crt` (full chain: server + intermediate) + `server.key`
- Prints the server cert fingerprint for pinning

### Step 3: Add cert pinning to client

In `src/qftls.rs`, add a pinning verifier:

```rust
/// Server certificate pinning verifier.
/// Compares the server's end-entity cert SHA-256 fingerprint to a known-good value.
pub struct PinnedCertVerifier {
    expected_fingerprint: [u8; 32],
}

impl PinnedCertVerifier {
    pub fn new(fingerprint: &str) -> Result<Self, ConnectionError> {
        let bytes: Vec<u8> = fingerprint.split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { expected_fingerprint: arr })
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(end_entity.as_ref());
        if hash.as_slice() == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {}, got {}",
                hex::encode(self.expected_fingerprint),
                hex::encode(hash)
            )))
        }
    }
    // ... verify_tls12_signature, verify_tls13_signature ...
}
```

Add `--pin-cert <FINGERPRINT>` CLI flag to the client command in `src/main.rs`. When set,
use `PinnedCertVerifier` instead of the standard CA-based verifier.

### Step 4: Add cert expiration checking on load

In `load_certs_from_file()` (`src/qftls.rs:1309`), after loading certs, check expiration:

```rust
fn load_certs_from_file() -> Result<Vec<CertificateDer<'static>>, ConnectionError> {
    // ... existing loading logic ...

    // Check expiration of the first (end-entity) cert
    if let Some(cert) = certs.first() {
        match check_cert_expiration(cert.as_ref(), 30) {
            Ok(CertExpiry::Expired { not_after }) => {
                log::error!(
                    "Server certificate EXPIRED on {}. TLS handshakes will fail.",
                    not_after
                );
            }
            Ok(CertExpiry::ExpiringSoon { not_after, days_left }) => {
                log::warn!(
                    "Server certificate expires in {} days ({}). Plan rotation.",
                    days_left, not_after
                );
            }
            Ok(CertExpiry::Valid { not_after, days_left }) => {
                log::info!("Server certificate valid for {} more days (until {})", days_left, not_after);
            }
            Err(e) => {
                log::warn!("Could not check cert expiration: {}", e);
            }
        }
    }

    Ok(certs)
}
```

### Step 5: Add cert rotation (SIGHUP reload)

Add a SIGHUP handler in the server main loop (`src/main.rs`) that triggers cert reload:

```rust
// In server mode, install SIGHUP handler for cert rotation
let reload_tx = engine.reload_channel();
tokio::spawn(async move {
    let mut sig = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::hangup()
    ).unwrap();
    while sig.recv().await.is_some() {
        log::info!("SIGHUP received, reloading TLS certificates");
        // Re-read cert/key from the override paths
        // Update the rustls ServerConfig with new certs
        let _ = reload_tx.send(ReloadAction::TlsCerts);
    }
});
```

In `qftls.rs`, add a method to reload certs without recreating the entire connection:

```rust
/// Reload TLS certificates from disk. Called on SIGHUP.
pub fn reload_server_certs() -> Result<(), ConnectionError> {
    let certs = Self::load_certs_from_file()?;
    let key = Self::load_private_key()?;
    // Update the server config in place (requires Arc<ServerConfig> swap)
    // The new config takes effect for new connections; existing connections
    // continue with their negotiated keys.
    Ok(())
}
```

### Step 6: Remove self-signed fallback in release builds

In `create_server_connection()` (`src/qftls.rs:1228`), make the fallback conditional:

```rust
if TLS_OVERRIDE_REQUIRED.load(Ordering::Relaxed) {
    // ... error as before ...
}
#[cfg(feature = "dev-certs")]
{
    log::warn!("No TLS cert/key found. Generating ephemeral self-signed cert (dev-certs feature).");
    Self::generate_ephemeral_self_signed()?
}
#[cfg(not(feature = "dev-certs"))]
{
    return Err(ConnectionError::TlsError(
        "No TLS cert/key found and self-signed fallback disabled in release build. \
         Run 'quicfuscate-ctl cert generate-ca' and 'quicfuscate-ctl cert generate-server' \
         to create certificates.".to_string()
    ));
}
```

The `dev-certs` feature already exists in `Cargo.toml` (line 115). Release builds
(`cargo build --release` without `--features dev-certs`) will fail hard if no certs are
found, forcing operators to generate proper certs.

### Step 7: Add cert chain support

Ensure `load_certs_from_file()` loads the full chain (server cert + intermediate CA) from
a single PEM file or a chain file. rustls requires the full chain to be sent during the
handshake so the client can build the chain to the root CA.

`CertificateDer::pem_slice_iter` (line 1314) already loads all certs from a PEM file —
so if the server cert file contains `server.crt + intermediate.crt` concatenated, the
chain is loaded correctly. Document this in the cert generation CLI output:

```
Server certificate chain written to: config/local/pki/server.crt
  - Server cert (CN=vpn.example.com, valid 365 days)
  - Intermediate CA (CN=QuicFuscate Intermediate CA, valid 1825 days)
Private key written to: config/local/pki/server.key
Fingerprint: ab:cd:ef:12:34:56:...
```

### Step 8: Add CRL support (basic)

Add a CRL distribution point to generated server certs. Add CRL checking to the client
verifier:

```rust
/// Load a CRL file and check if the server cert is revoked.
pub fn check_crl(cert_der: &[u8], crl_path: &Path) -> Result<bool, PkiError> {
    // Parse CRL, check if cert serial is in the revoked list
    // Return true if revoked
}
```

Add `--crl-file` CLI flag to the client. If set, the client checks the server cert against
the CRL on every connection.

### Step 9: Tests

- **Unit test:** `generate_root_ca` produces a valid CA cert with correct key usage
  (keyCertSign, cRLSign).
- **Unit test:** `generate_server_cert` produces a cert signed by the intermediate CA.
  Verify the signature chain: server → intermediate → root.
- **Unit test:** `cert_fingerprint` produces the correct SHA-256 hash (verify against
  a known cert with a known fingerprint).
- **Unit test:** `check_cert_expiration` returns `Expired` for a cert with `not_after`
  in the past, `ExpiringSoon` for <30 days, `Valid` for >30 days.
- **Unit test:** `PinnedCertVerifier` accepts a cert with matching fingerprint, rejects
  one with mismatched fingerprint.
- **Integration test:** Generate CA → generate server cert → start server with cert →
  client connects with `--ca-file ca-root.crt` → handshake succeeds, cert chain validates.
- **Integration test:** Client with `--pin-cert <fingerprint>` → handshake succeeds with
  matching fingerprint, fails with wrong fingerprint.
- **Integration test:** Release build (no `dev-certs` feature) → server without cert files
  → startup fails with error message (no self-signed fallback).
- **Integration test:** SIGHUP → cert reload → new connections use new cert.
- **Integration test:** Expired cert → server logs error, client handshake fails.

## Files to Modify/Create

- `src/pki.rs` (new) — CA generation, server cert signing, fingerprint computation,
  expiration checking, CRL checking.
- `src/qftls.rs` — add `PinnedCertVerifier`, add cert expiration check in
  `load_certs_from_file()`, add `reload_server_certs()`, make self-signed fallback
  conditional on `dev-certs` feature.
- `src/bin/quicfuscate-ctl.rs` — add `cert` subcommand with `generate-ca`,
  `generate-server`, `inspect`, `fingerprint` subcommands.
- `src/main.rs` — add `--pin-cert <FINGERPRINT>` to client command, add `--crl-file` to
  client command, add SIGHUP handler for cert reload in server mode.
- `Cargo.toml` — add `sha2` dependency (if not already present), add `hex` dependency,
  add `time` dependency for cert validity dates.
- `config/local/pki/` (new directory) — default output for cert generation CLI.

## Acceptance Criteria

- [ ] `quicfuscate-ctl cert generate-ca` generates root CA + intermediate CA with correct
      key usage and validity periods.
- [ ] `quicfuscate-ctl cert generate-server` generates a server cert signed by the
      intermediate CA, with correct SANs and EKU (serverAuth).
- [ ] Server cert chain (server + intermediate) is sent during TLS handshake.
- [ ] Client connects with `--ca-file ca-root.crt` → handshake succeeds, chain validates
      to root CA.
- [ ] Client with `--pin-cert <fingerprint>` → handshake succeeds with matching fingerprint.
- [ ] Client with `--pin-cert <wrong-fingerprint>` → handshake fails with clear error.
- [ ] Server logs warning if cert expires within 30 days.
- [ ] Server logs error if cert is already expired.
- [ ] SIGHUP triggers cert reload; new connections use new cert.
- [ ] Release build (no `dev-certs` feature) without cert files → server fails to start
      with clear error message.
- [ ] Dev build (`dev-certs` feature) without cert files → self-signed fallback works
      (backward compatible).
- [ ] `quicfuscate-ctl cert inspect --cert server.crt` prints cert details (CN, SANs,
      issuer, validity, fingerprint).
- [ ] `quicfuscate-ctl cert fingerprint --cert server.crt` prints SHA-256 fingerprint.
- [ ] CRL checking works with `--crl-file` (revoked cert → handshake fails).
- [ ] `cargo build --release` clean (without `dev-certs`), `cargo clippy --lib -D warnings` green.
- [ ] All unit and integration tests pass.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| generate_root_ca | <100ms | KeyPair::generate + cert signing |
| generate_server_cert | <50ms | Sign with existing CA key |
| cert_fingerprint (SHA-256) | <1us | Single hash of DER bytes |
| check_cert_expiration | <10us | Parse ASN.1 not_after from DER |
| PinnedCertVerifier::verify_server_cert | <5us | SHA-256 hash + compare |
| Cert reload on SIGHUP | <50ms | Re-read files + rebuild ServerConfig |
| CA cert storage | ~2KB | DER-encoded cert + key per file |
| Full PKI on disk | ~10KB | Root CA + intermediate + server cert + keys |
