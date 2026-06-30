---
id: TODO-434
title: Production PKI (CA hierarchy, cert generation, no self-signed fallback)
severity: HIGH
phase: "G"
priority: P0
status: OPEN
created: 2026-07-23
depends_on: []
---

# TODO-434: Production PKI (CA hierarchy, cert generation, no self-signed fallback)

## Goal
Replace the ephemeral self-signed certificate fallback with a full production PKI: a root CA, intermediate CA, and server certificate chain with OCSP stapling, CRL distribution, automated cert generation tooling, expiration monitoring, and hot-reload on file change. The system must produce certificates that are indistinguishable from real browser-trusted certs in the TLS handshake to preserve stealth.

## Current State (verified against code)

### Self-signed fallback (the problem)
- `src/qftls.rs:1228-1307` — `create_server_connection()` calls `load_certs_from_file()` and `load_private_key()`. If both fail and `TLS_OVERRIDE_REQUIRED` is false, it falls back to `generate_ephemeral_self_signed()` (line 1249), which generates a self-signed cert with `rcgen` using `CN=localhost`, `O=QuicFuscate`, SANs for localhost/127.0.0.1/::1.
- `src/qftls.rs:1234-1244` — When `TLS_OVERRIDE_REQUIRED` is true, the fallback is blocked and an error is returned. This flag is an AtomicBool loaded with `Ordering::Relaxed`.
- `src/qftls.rs:1278-1307` — `generate_ephemeral_self_signed()` uses `rcgen::CertificateParams` with a hardcoded DN and SANs. The cert is never persisted to disk — it is regenerated on every `create_server_connection()` call, meaning every connection gets a fresh ephemeral cert with no chain.

### Cert loading
- `src/qftls.rs:1309-1357` — `load_certs_from_file()` tries `TLS_CERT_PATH_OVERRIDE`, then standard paths: `certs/server.crt`, `/etc/quicfuscate/server.crt`, `server.crt`. `load_private_key()` mirrors this for `certs/server.key`, `/etc/quicfuscate/server.key`, `server.key`. No chain validation, no CA verification, no expiration checking.

### Server startup
- `src/main.rs:2170` — `load_server_identity(&mut config, cert_path, key_path)` is called with CLI-provided cert/key paths. No validation that the cert is signed by a trusted CA, no chain completeness check.
- `src/main.rs:2066-2098` — `run_server()` accepts `cert_path: &Path` and `key_path: &Path` from CLI args. No PKI subcommand exists.

### Dependencies
- `Cargo.toml` — `rcgen = { version = "0.13", optional = true }` (gated behind `server` and `dev-certs` features). `rustls = "0.23"` with `ring` feature. `rustls-native-certs = "0.8"`. No `x509-cert`, no `rcgen` CA chain support, no OCSP stapling integration.

## Problem Analysis

### Security implications
1. **Self-signed certs are a DPI signal**: A self-signed certificate with `CN=localhost` and `O=QuicFuscate` is trivially distinguishable from real browser-trusted traffic. DPI systems can fingerprint the issuer field, the lack of a CA chain, and the absence of OCSP/CRL URLs. This directly undermines the project's stealth goals.
2. **No revocation path**: There is no mechanism to revoke a compromised server certificate. No CRL, no OCSP responder, no stapling. A stolen key remains valid until natural expiration.
3. **No chain of trust**: The server presents a single self-signed cert. Real TLS connections present a chain (leaf → intermediate → root). The absence of a chain is itself a fingerprint.
4. **No expiration monitoring**: Certificates can silently expire, causing connection failures that are hard to diagnose.

### Why current state is insufficient
- The `TLS_OVERRIDE_REQUIRED` flag is a band-aid: it prevents the fallback but provides no alternative path for generating proper certs.
- `rcgen` is already a dependency but is only used for ephemeral self-signed generation, not for CA hierarchy creation.
- There is no CLI tooling for cert lifecycle management (generation, signing, renewal, revocation).
- The cert loading path has no validation: it will happily load an expired cert, a cert with wrong SANs, or an incomplete chain.

## Proposed Architecture

### Component overview
```
┌─────────────────────────────────────────────────────────────┐
│                    quicfuscate pki CLI                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │  init    │  │  sign    │  │  revoke  │  │  verify     │ │
│  │ (root+   │  │ (server │  │ (CRL     │  │ (chain      │ │
│  │  inter)  │  │  cert)  │  │  update) │  │  validation)│ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬──────┘ │
│       │              │              │               │        │
│       ▼              ▼              ▼               ▼        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              PKI Store (filesystem)                   │   │
│  │  /etc/quicfuscate/pki/                                │   │
│  │  ├── root-ca.key + root-ca.crt                        │   │
│  │  ├── intermediate-ca.key + intermediate-ca.crt        │   │
│  │  ├── server.key + server.crt (full chain)             │   │
│  │  ├── crl.pem (revocation list)                        │   │
│  │  └── ocsp-responder.db (optional)                     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              CertLoader (runtime, in qftls.rs)               │
│  • Loads full chain (leaf + intermediate)                    │
│  • Validates chain to root CA                                │
│  • Checks expiration (warns at 80%, rejects at 100%)        │
│  • Hot-reloads on file change (inotify/kqueue)              │
│  • Staples OCSP response (if OCSP URL present)              │
│  • Serves CRL distribution point URL in cert extension      │
└─────────────────────────────────────────────────────────────┘
```

### Data flows
1. **Init**: `quicfuscate pki init --root-cn="..." --intermediate-cn="..."` → generates root CA key+cert (self-signed, 20yr), intermediate CA key+cert (signed by root, 10yr), stores in `/etc/quicfuscate/pki/`.
2. **Sign**: `quicfuscate pki sign --domain="vpn.example.com" --san="..." --days=90` → generates server key, creates CSR, signs with intermediate CA, embeds OCSP URL + CRL DP URL, outputs `server.crt` (leaf+intermediate chain) + `server.key`.
3. **Runtime load**: `CertLoader` on startup reads `server.crt` + `server.key`, validates chain to root, checks expiration, staples OCSP if configured.
4. **Hot-reload**: `CertWatcher` monitors cert files via `notify` crate (inotify on Linux, kqueue on macOS). On change, atomically swaps the `rustls::ServerConfig` with a new cert chain. Active connections continue with old config; new connections use the new cert.
5. **Revoke**: `quicfuscate pki revoke --serial=0x...` → updates CRL, writes `crl.pem`. Server hot-reloads CRL for client-side verification (if mTLS enabled).

### Interfaces
```rust
// New module: src/pki/mod.rs
pub struct PkiConfig {
    pub store_path: PathBuf,
    pub root_ca_path: PathBuf,
    pub intermediate_ca_path: PathBuf,
    pub ocsp_responder_url: Option<String>,
    pub crl_distribution_url: Option<String>,
    pub key_algorithm: KeyAlgorithm, // ECDSA P-256 (default) or Ed25519
    pub signature_algorithm: SignatureAlgorithm,
}

pub struct CertChain {
    pub leaf: CertificateDer<'static>,
    pub intermediate: CertificateDer<'static>,
    pub root: CertificateDer<'static>,
    pub private_key: PrivateKeyDer<'static>,
    pub not_after: SystemTime,
    pub not_before: SystemTime,
}

pub struct CertLoader {
    config: PkiConfig,
    current: ArcSwap<CertChain>,  // lock-free hot-reload
    watcher: Option<notify::RecommendedWatcher>,
}

impl CertLoader {
    pub fn load(&self) -> Result<Arc<CertChain>, PkiError>;
    pub fn validate_chain(&self, chain: &CertChain) -> Result<(), PkiError>;
    pub fn check_expiration(&self, chain: &CertChain) -> ExpirationStatus;
    pub fn start_watcher(&mut self) -> Result<(), PkiError>;
}

// CLI subcommands
pub enum PkiCommand {
    Init { root_cn: String, intermediate_cn: String, store_path: PathBuf },
    Sign { domain: String, sans: Vec<String>, days: u32, output_dir: PathBuf },
    Revoke { serial: String, crl_path: PathBuf },
    Verify { cert_path: PathBuf, chain_path: Option<PathBuf> },
    Info { cert_path: PathBuf },
}
```

## Implementation Plan

### Phase 1: PKI store and CA generation (CLI)
1. Create `src/pki/mod.rs` with `PkiConfig`, `PkiError`, `PkiCommand` types.
2. Implement `pki init` using `rcgen` to generate root CA (self-signed, 20yr, CA:TRUE, keyCertSign + cRLSign) and intermediate CA (signed by root, 10yr, CA:TRUE, pathlen:0).
3. Use ECDSA P-256 as default key algorithm (matches modern browser certs; smaller signatures, faster verification than RSA).
4. Store keys with `0600` permissions, certs with `0644`, using `fsutil::atomic_write_file`.
5. Add `pki` subcommand to `src/main.rs` clap `Commands` enum.

### Phase 2: Server cert signing (CLI)
1. Implement `pki sign` — generate server keypair, create CSR with SANs, sign with intermediate CA.
2. Embed CRL Distribution Points extension (RFC 5280 §4.2.1.13) pointing to `crl.pem` URL.
3. Embed Authority Information Access (AIA) extension with OCSP responder URL (if configured).
4. Embed SCT (Signed Certificate Timestamp) placeholder for future CT support.
5. Output full chain PEM (leaf + intermediate concatenated) as `server.crt`.
6. Validate: verify the generated chain back to root before writing.

### Phase 3: Runtime cert loading with chain validation
1. Refactor `load_certs_from_file()` in `src/qftls.rs` to load the full chain (all PEM blocks from `server.crt`).
2. Add chain validation: parse the chain, verify leaf is signed by intermediate, intermediate by root, using `rustls-webpki` or `x509-parser`.
3. Add expiration checking: compare `not_after` to current time. Log warning at 80% lifetime, error at 100%.
4. Remove the `generate_ephemeral_self_signed()` fallback entirely when `TLS_OVERRIDE_REQUIRED` is true (already done) — but also add a new `--require-prod-pki` CLI flag that makes the override required by default for server mode.

### Phase 4: Hot-reload via file watching
1. Add `notify = "6"` to Cargo.toml (cross-platform file watcher: inotify/kqueue/ReadDirectoryChangesW).
2. Implement `CertWatcher` in `src/pki/watcher.rs` that monitors `server.crt` and `server.key` for modifications.
3. On change: load new chain, validate, atomically swap via `arc-swap::ArcSwap` (already a dependency if present, or add `arc-swap = "1"`).
4. The QUIC server's `rustls::ServerConfig` is wrapped in `Arc<ArcSwap<ServerConfig>>`. New connections read the current config; active connections keep their existing config.
5. Debounce file events (100ms) to avoid reloading on partial writes.

### Phase 5: OCSP stapling and CRL
1. If OCSP responder URL is configured, fetch and staple OCSP response using `rustls` server config's `with_single_cert_ocsp_and_key()` or manual stapling via `ServerConfig::ocsp_response`.
2. Implement a lightweight OCSP responder (optional, behind feature flag `ocsp-responder`) that serves pre-signed OCSP responses from `ocsp-responder.db`.
3. Generate CRL on `pki revoke` using `rcgen` CRL support or `x509-cert` crate.
4. Serve CRL via the admin HTTP server at a configurable URL path (e.g., `/crl.pem`).
5. Note: Let's Encrypt dropped OCSP in May 2025 in favor of CRLs. For private PKI, CRLs are the standard. Prioritize CRL over OCSP for the internal CA; support OCSP stapling for compatibility with externally-issued certs.

### Phase 6: Let's Encrypt integration (production stealth)
1. Add `pki acme` subcommand that uses the ACME protocol (via `instant-acme` crate or raw implementation) to obtain real browser-trusted certs from Let's Encrypt.
2. Challenge type: DNS-01 (preferred for VPN servers that don't serve HTTP on port 80) or TLS-ALPN-01.
3. Store LE certs in the same PKI store, with automatic renewal at 30 days before expiration.
4. This is the recommended production path: certs are signed by a real CA, indistinguishable from normal HTTPS traffic.

## Technology Choices

### Chosen: `rcgen` 0.13 for CA/cert generation + `rustls` 0.23 for runtime
- **rcgen** is already a dependency. Version 0.13 supports CA extensions, CSR signing, CRL generation, and ECDSA P-256. It is the most mature pure-Rust cert generation crate.
- **rustls** 0.23 supports OCSP stapling via `ServerConfig::ocsp_response` and CRL-based revocation via `rustls-webpki::RevocationOptionsBuilder`.
- **rustls-webpki** provides `RevocationOptionsBuilder` for CRL-based revocation checking with configurable depth, status policy, and expiration policy.

### Chosen: `notify` 6 for file watching
- Cross-platform (inotify/kqueue/ReadDirectoryChangesW). Mature, widely used. Debounce via `notify-debouncer-mini` or manual debounce.

### Chosen: `x509-parser` for runtime cert inspection
- Lightweight, no_std-compatible. Used for reading `not_after`, SANs, serial number, extensions without full rustls validation overhead. Alternative: `x509-cert` (from RustCrypto) — more type-safe but heavier.

### Evaluated and rejected
- **OpenSSL/libssl**: Rejected — adds a C dependency, breaks the pure-Rust crypto story, and `rcgen`+`rustls` cover all needed functionality.
- **step-ca / smallstep**: Rejected — external service, adds operational complexity. The CLI tooling should be self-contained.
- **HashiCorp Vault PKI**: Rejected for the same reason — external dependency. Could be documented as an alternative for enterprise deployments.
- **CFSSL**: Rejected — Go-based, external binary.

### Key algorithm: ECDSA P-256 (prime256v1/secp256r1)
- Modern browsers use ECDSA P-256 for the majority of TLS 1.3 connections.
- Smaller signatures (64 bytes vs 256+ for RSA 2048), faster verification.
- Matches what DPI expects to see in "normal" HTTPS traffic.
- Alternative: Ed25519 (even faster, smaller) — but some older DPI systems may not expect it. Use Ed25519 for internal CA keys, ECDSA P-256 for server certs.

## Stealth/Efficiency Considerations

### Stealth
- **Cert must look real**: The leaf cert must have a real domain in SAN, a real CA as issuer, proper extensions (EKU=serverAuth, keyUsage=digitalSignature+keyEncipherment), and a chain. Self-signed certs with `O=QuicFuscate` are an immediate red flag.
- **OCSP/CRL URLs**: Real certs have these. Their presence is expected; their absence is notable. For private PKI, include CRL DP URLs even if the CRL is served locally.
- **Let's Encrypt path**: For maximum stealth, use LE-issued certs. The TLS handshake is then byte-identical to a normal HTTPS connection to a real domain.
- **Cert key algorithm**: ECDSA P-256 matches the majority of real TLS 1.3 handshakes. Using RSA or Ed25519 exclusively could be a fingerprint.

### Performance
- **Hot-reload via ArcSwap**: Zero-copy, lock-free. New connections get the new config with no contention. Active connections are unaffected.
- **OCSP stapling**: Eliminates per-connection OCSP fetch by the client, reducing latency. The server fetches the OCSP response periodically (every 4-8 hours) and staples it.
- **CRL caching**: CRLs are cached in memory and refreshed periodically. No per-connection CRL fetch.
- **Cert validation at load time only**: Chain validation happens once on load/hot-reload, not per connection. The `rustls::ServerConfig` is pre-validated.

## Testing Plan

### Unit tests
- `pki init` generates valid root + intermediate with correct extensions (CA:TRUE, keyCertSign, cRLSign, pathlen).
- `pki sign` generates a server cert that validates against the generated chain.
- `CertLoader::validate_chain` rejects: expired cert, wrong SAN, broken chain, self-signed cert without CA flag.
- `CertLoader::check_expiration` returns correct status at 0%, 50%, 80%, 95%, 100% of lifetime.
- CRL generation includes revoked serial, correct signature, valid `nextUpdate`.
- Key generation: ECDSA P-256 keys are correct curve, correct length.

### Integration tests
- Full lifecycle: `pki init` → `pki sign` → load in server → client connects with chain validation → handshake succeeds.
- Hot-reload: start server with cert A, replace cert file with cert B, verify new connections use cert B while existing connections keep cert A.
- Expiration: generate cert with 1-second lifetime, verify server rejects it after expiry.
- CRL revocation: revoke a cert, verify client-side revocation check rejects it.

### E2E tests
- Server with LE-staged cert (using Let's Encrypt staging environment) — full handshake, data transfer, reconnection.
- Cert rotation under load: 100 active connections, hot-reload cert, verify zero dropped connections.

## Files to Create/Modify

### New files
- `src/pki/mod.rs` — PKI module root: `PkiConfig`, `PkiError`, `CertChain`, `CertLoader`
- `src/pki/ca.rs` — CA generation (root, intermediate) using rcgen
- `src/pki/sign.rs` — Server cert signing (CSR generation, signing, chain assembly)
- `src/pki/crl.rs` — CRL generation and management
- `src/pki/ocsp.rs` — OCSP stapling support (fetch, cache, serve)
- `src/pki/watcher.rs` — File watcher for hot-reload
- `src/pki/cli.rs` — CLI subcommand handlers for `pki init/sign/revoke/verify/info/acme`
- `tests/pki_lifecycle.rs` — Integration tests for full PKI lifecycle
- `tests/pki_hot_reload.rs` — Hot-reload integration tests

### Modified files
- `src/main.rs` — Add `Pki` variant to `Commands` enum, wire to `src/pki/cli.rs`
- `src/qftls.rs` — Refactor `load_certs_from_file()` to use `CertLoader`, add chain validation, add expiration check, integrate hot-reload via `ArcSwap<ServerConfig>`
- `Cargo.toml` — Add `notify = "6"`, `x509-parser = "0.16"`, `arc-swap = "1"` (if not present), make `rcgen` non-optional for server feature
- `src/lib.rs` — Add `pub mod pki;`

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| rcgen CRL support is limited (no delta CRLs, no indirect CRLs) | Use full CRLs only (sufficient for private PKI with <1000 certs). Document limitation. |
| Hot-reload race: file half-written when watcher fires | Debounce 100ms + validate chain before swap; if validation fails, keep old cert and log error. |
| OCSP responder availability: if OCSP server is down, stapling fails | Fall back to no-staple (rustls handles gracefully). For private PKI, prefer CRL-only. |
| Let's Encrypt rate limits (50 certs/week/domain) | Use staging environment for testing. Document rate limits. Support wildcard certs (*.domain) to reduce count. |
| Key file permissions on shared hosting | Enforce 0600 on key files, refuse to load world-readable keys in production mode. |
| ECDSA P-256 not supported by very old DPI systems | This is actually a benefit — old DPI that doesn't support ECDSA can't inspect the traffic. Modern DPI expects ECDSA. |
| Cert chain too long (3+ certs) increases handshake size | Limit to leaf + intermediate (2 certs). Root is not sent (client must have it). |

## Completion Criteria

- [ ] `quicfuscate pki init` generates root CA + intermediate CA with correct X.509 extensions
- [ ] `quicfuscate pki sign` generates a server cert signed by the intermediate CA, with CRL DP and OCSP AIA extensions
- [ ] `quicfuscate pki revoke` generates/updates a CRL with the revoked serial
- [ ] `quicfuscate pki verify` validates a cert chain back to the root CA
- [ ] `quicfuscate pki info` displays cert details (issuer, subject, SANs, serial, validity, extensions)
- [ ] Server loads the full cert chain (leaf + intermediate) on startup
- [ ] Chain validation rejects broken/expired/self-signed certs in production mode
- [ ] Expiration checking logs warnings at 80% and errors at 100% of cert lifetime
- [ ] Hot-reload swaps cert config atomically without dropping active connections
- [ ] OCSP stapling works when OCSP URL is present in cert
- [ ] CRL is served via admin HTTP server at configurable URL
- [ ] `generate_ephemeral_self_signed()` is removed or gated behind `--dev-certs` flag only
- [ ] Let's Encrypt ACME integration obtains real certs (staging environment for tests)
- [ ] All unit, integration, and E2E tests pass
- [ ] Documentation updated: PKI setup guide in docs/
