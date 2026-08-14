use super::*;
use parking_lot::Mutex;
#[cfg(debug_assertions)]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(debug_assertions)]
use rustls::pki_types::UnixTime;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
#[cfg(debug_assertions)]
use rustls::DigitallySignedStruct;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_native_certs::load_native_certs;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use webpki_roots;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StandardPacketOperation {
    Seal,
    Open,
}

#[cfg(test)]
thread_local! {
    static STANDARD_PACKET_OPERATIONS: std::cell::RefCell<Vec<StandardPacketOperation>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn observe_standard_packet_operation(operation: StandardPacketOperation) {
    STANDARD_PACKET_OPERATIONS.with(|operations| operations.borrow_mut().push(operation));
}

#[cfg(test)]
pub(super) fn take_standard_packet_operations() -> Vec<StandardPacketOperation> {
    STANDARD_PACKET_OPERATIONS.with(|operations| std::mem::take(&mut *operations.borrow_mut()))
}

enum PendingKeyChange {
    Handshake(QuicTlsHandshakeKeys),
    OneRtt(QuicTlsOneRttKeys),
}

pub(super) fn validate_server_identity_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(), ConnectionError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ConnectionError::TlsError(format!("Certificate parse failed: {error}")))?;
    if certs.is_empty() {
        return Err(ConnectionError::TlsError("Certificate chain must not be empty".to_string()));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|error| ConnectionError::TlsError(format!("Key parse failed: {error}")))?;
    ServerConfig::builder_with_provider(Arc::new(crypto_provider_without_chacha()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| {
            ConnectionError::TlsError(format!("TLS protocol validation failed: {error}"))
        })?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map(|_| ())
        .map_err(|error| {
            ConnectionError::TlsError(format!(
                "Certificate/private-key correspondence validation failed: {error}"
            ))
        })
}

/// rustls QUIC TLS provider with standard TLS ticket resumption and packet-key installation.
/// 0-RTT remains deliberately disabled until packet-level early-data keys exist.
/// Build the shared rustls provider with the project's real-TLS ChaCha policy.
///
/// This provider is used on both client and server connections. TLS Cover's
/// synthetic record cipher remains independently configurable and is not part
/// of this ClientHello negotiation policy.
fn crypto_provider_without_chacha() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| {
        !matches!(
            suite.suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        )
    });
    provider
}

fn standard_cipher_suite(
    suite: rustls::CipherSuite,
) -> Result<StandardCipherSuite, ConnectionError> {
    match suite {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(StandardCipherSuite::Aes128GcmSha256),
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => Ok(StandardCipherSuite::Aes256GcmSha384),
        unsupported => Err(ConnectionError::TlsError(format!(
            "negotiated unsupported QUIC TLS cipher suite: {unsupported:?}"
        ))),
    }
}

fn crypto_provider_for_profile(
    profile: &TlsProfile,
) -> Result<rustls::crypto::CryptoProvider, ConnectionError> {
    let mut provider = crypto_provider_without_chacha();
    let available = provider.cipher_suites.clone();
    let mut projected = Vec::with_capacity(profile.cipher_suites.len());

    for requested in &profile.cipher_suites {
        let requested = rustls::CipherSuite::from(*requested);
        if let Some(suite) = available.iter().copied().find(|suite| {
            suite.tls13().is_some()
                && suite.suite() == requested
                && standard_cipher_suite(suite.suite()).is_ok()
        }) {
            if !projected
                .iter()
                .any(|existing: &rustls::SupportedCipherSuite| existing.suite() == suite.suite())
            {
                projected.push(suite);
            }
        }
    }

    if projected.is_empty() {
        return Err(ConnectionError::TlsError(format!(
            "TLS profile '{}' has no supported TLS 1.3 AES-GCM cipher suite",
            profile.name
        )));
    }
    provider.cipher_suites = projected;
    Ok(provider)
}

#[derive(Debug)]
struct NoClientCertificate;

impl rustls::client::ResolvesClientCert for NoClientCertificate {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

static STANDARD_SESSION_STORE: OnceLock<Arc<rustls::client::ClientSessionMemoryCache>> =
    OnceLock::new();
static NO_CLIENT_CERTIFICATE: OnceLock<Arc<NoClientCertificate>> = OnceLock::new();
static STANDARD_SERVER_TICKETER: OnceLock<
    Result<Arc<dyn rustls::server::ProducesTickets>, String>,
> = OnceLock::new();
static STANDARD_VERIFIED_VERIFIERS: OnceLock<
    Mutex<HashMap<String, Arc<rustls::client::WebPkiServerVerifier>>>,
> = OnceLock::new();

fn no_client_certificate() -> Arc<NoClientCertificate> {
    NO_CLIENT_CERTIFICATE.get_or_init(|| Arc::new(NoClientCertificate)).clone()
}

fn standard_session_resumption() -> rustls::client::Resumption {
    let store: Arc<dyn rustls::client::ClientSessionStore> = STANDARD_SESSION_STORE
        .get_or_init(|| Arc::new(rustls::client::ClientSessionMemoryCache::new(256)))
        .clone();
    rustls::client::Resumption::store(store)
}

fn standard_server_ticketer() -> Result<Arc<dyn rustls::server::ProducesTickets>, ConnectionError> {
    STANDARD_SERVER_TICKETER
        .get_or_init(|| {
            rustls::crypto::ring::Ticketer::new().map_err(|error| {
                format!("standard TLS session-ticket key initialization failed: {error}")
            })
        })
        .clone()
        .map_err(ConnectionError::TlsError)
}

fn standard_verified_verifier(
    roots: &RootCertStore,
    verifier_key: &str,
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, ConnectionError> {
    let verifiers = STANDARD_VERIFIED_VERIFIERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut verifiers = verifiers.lock();
    if let Some(verifier) = verifiers.get(verifier_key) {
        return Ok(verifier.clone());
    }
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots.clone()),
        Arc::new(crypto_provider_without_chacha()),
    )
    .build()
    .map_err(|error| {
        ConnectionError::TlsError(format!(
            "standard TLS certificate verifier initialization failed: {error}"
        ))
    })?;
    verifiers.insert(verifier_key.to_owned(), verifier.clone());
    Ok(verifier)
}

pub struct RustlsProviderImpl {
    /// Active rustls QUIC connection (client or server side).
    pub connection: rustls::quic::Connection,
    /// Monotonic clock shared with the owning QUIC connection.
    pub clock: crate::time_source::ProtocolClock,
    /// Outgoing Initial CRYPTO stream owned by this TLS transcript.
    pub crypto_initial: qf_transport_crypto_stream::CryptoStream,
    /// Outgoing Handshake CRYPTO stream owned by this TLS transcript.
    pub crypto_handshake: qf_transport_crypto_stream::CryptoStream,
    /// Outgoing application-level CRYPTO stream owned by this TLS transcript.
    pub crypto_application: qf_transport_crypto_stream::CryptoStream,
    /// Packet-key changes awaiting synchronous transport installation.
    pending_key_changes: VecDeque<PendingKeyChange>,
    /// Whether the transport must discard keys from a replaced TLS transcript.
    reset_packet_keys: bool,
    /// True if this is a server-side provider.
    pub is_server: bool,
    /// Immutable environment generation used by this TLS runtime owner.
    #[cfg(debug_assertions)]
    pub environment: Arc<crate::env_utils::EnvSnapshot>,
    /// Whether the client verifies the server certificate.
    #[cfg(debug_assertions)]
    pub verify_peer: bool,
    /// Client-scoped CA bundle path copied from the owning transport config.
    pub client_ca_path: Option<String>,
    /// Whether the TLS handshake has completed.
    pub handshake_complete: bool,
    /// Current write-side encryption level.
    pub write_level: super::Level,
    /// Negotiated ALPN protocol string.
    pub alpn: Option<String>,
    /// DER-encoded peer certificate (if verified).
    pub peer_cert: Option<Vec<u8>>,
    /// Whether 0-RTT early data is enabled.
    pub zero_rtt_enabled: bool,
    /// QUIC transport parameters to send to the peer.
    pub transport_params: Vec<u8>,
    /// QUIC wire version used by rustls for TLS-derived packet protection.
    pub quic_version: rustls::quic::Version,
    /// Peer's QUIC transport parameters (received during handshake).
    pub peer_transport_params: Option<Vec<u8>>,
    /// Active TLS profile configuration.
    pub profile: Option<TlsProfile>,
    /// Earliest instant at which profile-gated handshake bytes may be emitted.
    pub profile_ready_at: Option<Instant>,
    /// Next 1-RTT secrets for key update.
    pub next_1rtt_secrets: Option<rustls::quic::Secrets>,
    /// Pending local 1-RTT packet keys queued during key update.
    pub pending_local_1rtt: VecDeque<std::sync::Arc<dyn rustls::quic::PacketKey>>,
    /// Pending remote 1-RTT packet keys queued during key update.
    pub pending_remote_1rtt: VecDeque<std::sync::Arc<dyn rustls::quic::PacketKey>>,

    /// Reusable buffer for CRYPTO frame serialization.
    pub crypto_buffer: Vec<u8>,
    /// Queued CRYPTO frames awaiting transmission.
    pub frame_buffer: Vec<(Level, Vec<u8>)>,

    /// Timestamp when the handshake started (for latency measurement).
    pub handshake_start: std::time::Instant,
    /// Total CRYPTO bytes sent.
    pub bytes_sent: usize,
    /// Total CRYPTO bytes received.
    pub bytes_received: usize,
}

pub(super) const DEFAULT_MAX_UDP_PAYLOAD_SIZE: usize = 1472;

/// Insecure verifier used only when explicitly requested via env.
/// Only available in debug builds to prevent accidental production use.
#[cfg(debug_assertions)]
#[derive(Debug)]
struct InsecureAcceptAllVerifier;

#[cfg(debug_assertions)]
fn insecure_verifier() -> Arc<InsecureAcceptAllVerifier> {
    static VERIFIER: OnceLock<Arc<InsecureAcceptAllVerifier>> = OnceLock::new();
    VERIFIER.get_or_init(|| Arc::new(InsecureAcceptAllVerifier)).clone()
}

#[cfg(debug_assertions)]
impl ServerCertVerifier for InsecureAcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

impl RustlsProviderImpl {
    #[cfg(test)]
    pub fn new_with_ca(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
    ) -> Result<Self, ConnectionError> {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_ca_with_snapshot(
            is_server,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            &environment,
        )
    }

    #[allow(dead_code)]
    pub fn new_with_ca_with_snapshot(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca_with_snapshot_and_clock(
            is_server,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            environment,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ca_with_snapshot_and_clock(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca_with_snapshot_and_clock_and_max_udp_payload(
            is_server,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            environment,
            clock,
            DEFAULT_MAX_UDP_PAYLOAD_SIZE,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ca_with_snapshot_and_clock_and_max_udp_payload(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
        clock: &crate::time_source::ProtocolClock,
        max_udp_payload_size: usize,
    ) -> Result<Self, ConnectionError> {
        let quic_version = Self::map_quic_version(version)?;
        let mut transport_params = Self::default_transport_params(max_udp_payload_size)?;
        transport_params.extend_from_slice(version_information_parameter);
        let client_ca_path = client_ca_path.map(str::to_owned);
        let connection = if is_server {
            Self::create_server_connection(quic_version, transport_params.clone())?
        } else {
            Self::create_client_connection(
                verify_peer,
                quic_version,
                transport_params.clone(),
                client_ca_path.as_deref(),
                environment,
            )?
        };
        let this = Self {
            connection,
            clock: clock.clone(),
            crypto_initial: qf_transport_crypto_stream::CryptoStream::new(),
            crypto_handshake: qf_transport_crypto_stream::CryptoStream::new(),
            crypto_application: qf_transport_crypto_stream::CryptoStream::new(),
            pending_key_changes: VecDeque::new(),
            reset_packet_keys: false,
            is_server,
            #[cfg(debug_assertions)]
            environment: Arc::new(environment.clone()),
            #[cfg(debug_assertions)]
            verify_peer,
            client_ca_path,
            handshake_complete: false,
            write_level: super::Level::Initial,
            alpn: None,
            peer_cert: None,
            zero_rtt_enabled: false,
            transport_params,
            quic_version,
            peer_transport_params: None,
            profile: None,
            profile_ready_at: None,
            next_1rtt_secrets: None,
            pending_local_1rtt: VecDeque::new(),
            pending_remote_1rtt: VecDeque::new(),
            crypto_buffer: Vec::with_capacity(4096),
            frame_buffer: Vec::new(),
            handshake_start: clock.now(),
            bytes_sent: 0,
            bytes_received: 0,
        };

        Ok(this)
    }

    fn map_quic_version(version: u32) -> Result<rustls::quic::Version, ConnectionError> {
        match version {
            PROTOCOL_VERSION => Ok(rustls::quic::Version::V1),
            PROTOCOL_VERSION_V2 => Ok(rustls::quic::Version::V2),
            _ => Err(ConnectionError::VersionMismatch),
        }
    }

    fn queue_crypto_bytes(
        &mut self,
        level: super::Level,
        data: &[u8],
    ) -> Result<(), ConnectionError> {
        if data.is_empty() {
            return Ok(());
        }
        let result = match level {
            super::Level::Initial => self.crypto_initial.send(data),
            super::Level::Handshake => self.crypto_handshake.send(data),
            _ => self.crypto_application.send(data),
        };
        result?;
        self.bytes_sent = self.bytes_sent.saturating_add(data.len());
        Ok(())
    }

    fn crypto_stream_mut(
        &mut self,
        level: super::Level,
    ) -> &mut qf_transport_crypto_stream::CryptoStream {
        match level {
            super::Level::Initial => &mut self.crypto_initial,
            super::Level::Handshake => &mut self.crypto_handshake,
            _ => &mut self.crypto_application,
        }
    }

    fn queue_key_change(&mut self, kc: rustls::quic::KeyChange) -> Result<(), ConnectionError> {
        let negotiated = self
            .connection
            .negotiated_cipher_suite()
            .ok_or_else(|| {
                ConnectionError::TlsError(
                    "rustls emitted QUIC keys before exposing the negotiated cipher suite"
                        .to_string(),
                )
            })
            .and_then(|suite| standard_cipher_suite(suite.suite()))?;
        match kc {
            rustls::quic::KeyChange::Handshake { keys } => {
                super::trace_key_change(self.is_server, "Handshake");
                self.pending_key_changes
                    .push_back(PendingKeyChange::Handshake(Self::handshake_keys(keys, negotiated)));
                self.write_level = super::Level::Handshake;
            }
            rustls::quic::KeyChange::OneRtt { keys, next } => {
                super::trace_key_change(self.is_server, "OneRtt");
                self.pending_key_changes
                    .push_back(PendingKeyChange::OneRtt(Self::one_rtt_keys(keys, negotiated)));
                self.next_1rtt_secrets = Some(next);
                self.write_level = super::Level::Application;
            }
        }
        Ok(())
    }

    fn flush_handshake_io(&mut self) -> Result<(), ConnectionError> {
        if let Some(ready_at) = self.profile_ready_at {
            if self.clock.now() < ready_at {
                return Ok(());
            }
            self.profile_ready_at = None;
        }
        // Emit handshake bytes; rustls signals key transitions via KeyChange.
        // When KeyChange is returned, the keys must be used for future handshake data,
        // which we model by updating `write_level` after queueing any bytes produced.
        for _ in 0..16 {
            self.crypto_buffer.clear();
            let kc = self.connection.write_hs(&mut self.crypto_buffer);
            let produced = !self.crypto_buffer.is_empty();
            if produced {
                let level = self.write_level;
                let pending = std::mem::take(&mut self.crypto_buffer);
                self.queue_crypto_bytes(level, &pending)?;
            }
            if let Some(kc) = kc {
                self.queue_key_change(kc)?;
                continue;
            }
            // No key change signaled; if no data was produced, we're done.
            if !produced {
                break;
            }
        }
        Ok(())
    }

    fn handshake_keys(
        keys: rustls::quic::Keys,
        standard_cipher_suite: StandardCipherSuite,
    ) -> QuicTlsHandshakeKeys {
        let local_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.local.packet.into();
        let remote_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.remote.packet.into();
        let local_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
            keys.local.header.into();
        let remote_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
            keys.remote.header.into();

        QuicTlsHandshakeKeys {
            seal: Box::new(RustlsPacketSeal { key: local_pkt }),
            open: Box::new(RustlsPacketOpen { key: remote_pkt }),
            hp_seal: Box::new(RustlsHp { key: local_hp }),
            hp_open: Box::new(RustlsHp { key: remote_hp }),
            standard_cipher_suite,
        }
    }

    fn one_rtt_keys(
        keys: rustls::quic::Keys,
        standard_cipher_suite: StandardCipherSuite,
    ) -> QuicTlsOneRttKeys {
        let local_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.local.packet.into();
        let remote_pkt: std::sync::Arc<dyn rustls::quic::PacketKey> = keys.remote.packet.into();
        let local_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
            keys.local.header.into();
        let remote_hp: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey> =
            keys.remote.header.into();

        QuicTlsOneRttKeys {
            seal: Arc::new(qf_crypto::PacketAeadSeal::dynamic(Box::new(RustlsPacketSeal {
                key: local_pkt,
            }))),
            open: Arc::new(qf_crypto::PacketAeadOpen::dynamic(Box::new(RustlsPacketOpen {
                key: remote_pkt,
            }))),
            hp_seal: Arc::new(RustlsHp { key: local_hp }),
            hp_open: Arc::new(RustlsHp { key: remote_hp }),
            standard_cipher_suite,
        }
    }

    /// Build the client root certificate store: native/webpki roots plus any CA
    /// supplied by the owning transport configuration.
    fn build_client_root_store(ca_path: Option<&str>) -> Result<RootCertStore, ConnectionError> {
        let mut roots = RootCertStore::empty();
        let native = load_native_certs();
        if !native.errors.is_empty() {
            log::warn!(
                "Native cert load had {} errors; continuing with {} certs",
                native.errors.len(),
                native.certs.len()
            );
        }
        if native.certs.is_empty() {
            log::warn!("No native certs loaded, using webpki roots");
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for cert in native.certs {
                roots.add(cert).map_err(|e| {
                    ConnectionError::TlsError(format!("Failed to add native cert: {}", e))
                })?;
            }
        }
        // Load the client-scoped CA bundle if configured.
        if let Some(ca_path) = ca_path {
            let ca_data = std::fs::read(ca_path).map_err(|e| {
                ConnectionError::TlsError(format!("CA file read failed ({}): {}", ca_path, e))
            })?;
            let ca_certs = rustls::pki_types::CertificateDer::pem_slice_iter(&ca_data)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    ConnectionError::TlsError(format!("CA file parse failed ({}): {}", ca_path, e))
                })?;
            if ca_certs.is_empty() {
                return Err(ConnectionError::TlsError(format!(
                    "CA file parse failed ({}): no certificates found",
                    ca_path
                )));
            }
            for cert in ca_certs {
                roots.add(cert).map_err(|e| {
                    ConnectionError::TlsError(format!("Failed to add CA cert: {}", e))
                })?;
            }
            log::info!("Loaded client-scoped CA certificates: {}", ca_path);
        }
        Ok(roots)
    }

    fn create_client_connection(
        verify_peer: bool,
        quic_version: rustls::quic::Version,
        transport_params: Vec<u8>,
        ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<rustls::quic::Connection, ConnectionError> {
        #[cfg(not(debug_assertions))]
        let _ = verify_peer;
        #[cfg(not(debug_assertions))]
        let _ = environment;
        let roots = Self::build_client_root_store(ca_path)?;

        let builder =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider_without_chacha()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| ConnectionError::TlsError(format!("Protocol version error: {}", e)))?;
        #[cfg(debug_assertions)]
        let allow_invalid =
            !verify_peer || environment.flag("QUICFUSCATE_ALLOW_INVALID_CERTS", false);
        #[cfg(not(debug_assertions))]
        let allow_invalid = false;
        let config = if allow_invalid {
            log::warn!("TLS certificate verification is disabled for this debug build");
            #[cfg(debug_assertions)]
            {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(insecure_verifier())
                    .with_client_cert_resolver(no_client_certificate())
            }
            #[cfg(not(debug_assertions))]
            {
                unreachable!("allow_invalid is always false in release builds")
            }
        } else if ca_path.is_none() {
            builder
                .with_webpki_verifier(standard_verified_verifier(&roots, "native")?)
                .with_client_cert_resolver(no_client_certificate())
        } else {
            builder
                .with_webpki_verifier(standard_verified_verifier(
                    &roots,
                    ca_path.unwrap_or_default(),
                )?)
                .with_client_cert_resolver(no_client_certificate())
        };

        let mut config = config;
        config.resumption = standard_session_resumption();
        // Enable QUIC
        config.enable_early_data = false;
        config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];
        // Performance settings
        config.max_fragment_size = Some(16384);
        config.enable_sni = true;

        let server_name = ServerName::try_from(DEFAULT_TLS_SNI_HOST)
            .map_err(|_| ConnectionError::TlsError("Invalid server name".into()))?;

        Ok(rustls::quic::Connection::Client(
            rustls::quic::ClientConnection::new(
                Arc::new(config),
                quic_version,
                server_name,
                transport_params,
            )
            .map_err(|e| ConnectionError::TlsError(format!("Client connection error: {}", e)))?,
        ))
    }

    fn create_server_connection(
        quic_version: rustls::quic::Version,
        transport_params: Vec<u8>,
    ) -> Result<rustls::quic::Connection, ConnectionError> {
        let certs_res = Self::load_certs_from_file();
        let key_res = Self::load_private_key();
        let (certs, key) = match (certs_res, key_res) {
            (Ok(c), Ok(k)) => (c, k),
            (cert_err, key_err) => {
                if TLS_OVERRIDE_REQUIRED.load(Ordering::Relaxed) {
                    let ce =
                        cert_err.err().map(|e| e.to_string()).unwrap_or_else(|| "-".to_string());
                    let ke =
                        key_err.err().map(|e| e.to_string()).unwrap_or_else(|| "-".to_string());
                    return Err(ConnectionError::TlsError(format!(
                        "TLS cert/key load failed (override required): cert={}, key={}",
                        ce, ke
                    )));
                }
                log::warn!(
	                        "No TLS cert/key found on disk. Generating ephemeral self-signed cert (development default)."
	                    );
                Self::generate_ephemeral_self_signed()?
            }
        };

        let config =
            ServerConfig::builder_with_provider(Arc::new(crypto_provider_without_chacha()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| ConnectionError::TlsError(format!("Protocol version error: {}", e)))?
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| ConnectionError::TlsError(format!("Cert error: {}", e)))?;

        let mut config = config;
        config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec()];
        config.max_early_data_size = MAX_EARLY_DATA_SIZE.load(Ordering::Relaxed);
        config.ticketer = standard_server_ticketer()?;
        config.send_tls13_tickets = 2;

        Ok(rustls::quic::Connection::Server(
            rustls::quic::ServerConnection::new(Arc::new(config), quic_version, transport_params)
                .map_err(|e| ConnectionError::TlsError(format!("Server connection error: {}", e)))?,
        ))
    }

    #[cfg(any(feature = "server", feature = "dev-certs"))]
    fn generate_ephemeral_self_signed() -> Result<
        (Vec<CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>),
        ConnectionError,
    > {
        use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CountryName, "US");
        params.distinguished_name.push(DnType::OrganizationName, "QuicFuscate");
        params.distinguished_name.push(DnType::CommonName, "localhost");
        let localhost_name = rcgen::Ia5String::try_from("localhost")
            .map_err(|_| ConnectionError::TlsError("Invalid SAN hostname".into()))?;
        params.subject_alt_names = vec![
            SanType::DnsName(localhost_name),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ];
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| ConnectionError::TlsError(format!("Key gen error: {}", e)))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| ConnectionError::TlsError(format!("Cert gen error: {}", e)))?;

        let certs = vec![CertificateDer::from(cert.der().to_vec())];
        let key_der = key_pair.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|_| ConnectionError::TlsError("Key conversion error".into()))?;
        Ok((certs, key))
    }

    fn load_certs_from_file() -> Result<Vec<CertificateDer<'static>>, ConnectionError> {
        if let Some(identity) = TLS_SERVER_IDENTITY_OVERRIDE.get() {
            return CertificateDer::pem_slice_iter(&identity.cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    ConnectionError::TlsError(format!(
                        "Preloaded certificate parse failed: {error}"
                    ))
                });
        }
        if let Some(path) = TLS_CERT_PATH_OVERRIDE.get().map(|s| s.as_str()) {
            let cert_data = std::fs::read(path).map_err(|e| {
                ConnectionError::TlsError(format!("Cert read failed ({}): {}", path, e))
            })?;
            let certs =
                CertificateDer::pem_slice_iter(&cert_data).collect::<Result<Vec<_>, _>>().map_err(
                    |e| ConnectionError::TlsError(format!("Cert parse failed ({}): {}", path, e)),
                )?;
            return Ok(certs);
        }

        // Try standard locations
        let cert_paths = vec!["certs/server.crt", "/etc/quicfuscate/server.crt", "server.crt"];
        for path in cert_paths {
            if let Ok(cert_data) = std::fs::read(path) {
                if let Ok(certs) =
                    CertificateDer::pem_slice_iter(&cert_data).collect::<Result<Vec<_>, _>>()
                {
                    return Ok(certs);
                }
            }
        }
        Err(ConnectionError::TlsError("No valid certificates found".into()))
    }

    fn load_private_key() -> Result<rustls::pki_types::PrivateKeyDer<'static>, ConnectionError> {
        if let Some(identity) = TLS_SERVER_IDENTITY_OVERRIDE.get() {
            return PrivateKeyDer::from_pem_slice(identity.key_pem.as_slice()).map_err(|error| {
                ConnectionError::TlsError(format!("Preloaded private key parse failed: {error}"))
            });
        }
        if let Some(path) = TLS_KEY_PATH_OVERRIDE.get().map(|s| s.as_str()) {
            let key_data = Zeroizing::new(std::fs::read(path).map_err(|e| {
                ConnectionError::TlsError(format!("Key read failed ({}): {}", path, e))
            })?);
            let key = PrivateKeyDer::from_pem_slice(&key_data).map_err(|e| {
                ConnectionError::TlsError(format!("Key parse failed ({}): {}", path, e))
            })?;
            return Ok(key);
        }

        let key_paths = vec!["certs/server.key", "/etc/quicfuscate/server.key", "server.key"];
        for path in key_paths {
            if let Ok(key_data) = std::fs::read(path) {
                let key_data = Zeroizing::new(key_data);
                if let Ok(key) = PrivateKeyDer::from_pem_slice(&key_data) {
                    return Ok(key);
                }
            }
        }
        Err(ConnectionError::TlsError("No valid private key found".into()))
    }

    fn default_transport_params(max_udp_payload_size: usize) -> Result<Vec<u8>, ConnectionError> {
        if !(1200..=65_527).contains(&max_udp_payload_size) {
            return Err(ConnectionError::InvalidState);
        }
        // QUIC transport parameters in wire format
        let mut params = Vec::new();
        // max_idle_timeout (0x01) = 30000ms
        params.extend_from_slice(&[0x01, 0x02, 0x75, 0x30]);
        // max_udp_payload_size (0x03) follows the concrete transport budget of this hop.
        let mut parameter_id = [0u8; 8];
        let parameter_id_len = qf_transport_pn::varint::write_varint(0x03, &mut parameter_id)?;
        let mut parameter_value = [0u8; 8];
        let parameter_value_len = qf_transport_pn::varint::write_varint(
            max_udp_payload_size as u64,
            &mut parameter_value,
        )?;
        let mut parameter_length = [0u8; 8];
        let parameter_length_len = qf_transport_pn::varint::write_varint(
            parameter_value_len as u64,
            &mut parameter_length,
        )?;
        params.extend_from_slice(&parameter_id[..parameter_id_len]);
        params.extend_from_slice(&parameter_length[..parameter_length_len]);
        params.extend_from_slice(&parameter_value[..parameter_value_len]);
        // initial_max_data (0x04) = 10MB
        params.extend_from_slice(&[0x04, 0x03, 0x98, 0x96, 0x80]);
        // initial_max_stream_data_bidi_local (0x05) = 1MB
        params.extend_from_slice(&[0x05, 0x03, 0x0f, 0x42, 0x40]);
        // initial_max_stream_data_bidi_remote (0x06) = 1MB
        params.extend_from_slice(&[0x06, 0x03, 0x0f, 0x42, 0x40]);
        // initial_max_streams_bidi (0x08) = 100
        params.extend_from_slice(&[0x08, 0x01, 0x64]);
        // initial_max_streams_uni (0x09) = 100
        params.extend_from_slice(&[0x09, 0x01, 0x64]);
        Ok(params)
    }

    fn apply_profile_to_config(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
        // Store profile and schedule cosmetic timing without blocking the
        // caller. The synchronous provider API cannot await, so the
        // handshake I/O flush observes this deadline instead.
        self.profile = Some(profile.clone());
        let profile_ready_at = if profile.cover_performance_mode {
            None
        } else if let Some(jitter) = profile.timing_jitter {
            match self.clock.checked_deadline_after(jitter) {
                Some(ready_at) => Some(ready_at),
                None => {
                    log::warn!(
                        "TLS profile timing jitter deadline overflowed; continuing immediately"
                    );
                    None
                }
            }
        } else {
            None
        };
        // Best-effort reconfigure only for client side before handshake
        if let rustls::quic::Connection::Client(_) = &self.connection {
            self.rebuild_client_connection(profile)?;
        }
        self.profile_ready_at = profile_ready_at;
        Ok(())
    }

    fn rebuild_client_connection(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
        // Build a fresh ClientConfig with ALPN and early data settings based on profile.
        // Use the same client-scoped root store so the configured CA remains effective
        // after a profile or SNI rebuild.
        let roots = Self::build_client_root_store(self.client_ca_path.as_deref())?;
        let builder =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider_for_profile(profile)?))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| ConnectionError::TlsError(format!("Protocol version error: {}", e)))?;
        #[cfg(debug_assertions)]
        let allow_invalid =
            !self.verify_peer || self.environment.flag("QUICFUSCATE_ALLOW_INVALID_CERTS", false);
        #[cfg(not(debug_assertions))]
        let allow_invalid = false;
        let cfg = if allow_invalid {
            log::warn!("TLS certificate verification is disabled for this debug build");
            #[cfg(debug_assertions)]
            {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(insecure_verifier())
                    .with_client_cert_resolver(no_client_certificate())
            }
            #[cfg(not(debug_assertions))]
            {
                unreachable!("allow_invalid is always false in release builds")
            }
        } else if self.client_ca_path.is_none() {
            builder
                .with_webpki_verifier(standard_verified_verifier(&roots, "native")?)
                .with_client_cert_resolver(no_client_certificate())
        } else {
            builder
                .with_webpki_verifier(standard_verified_verifier(
                    &roots,
                    self.client_ca_path.as_deref().unwrap_or_default(),
                )?)
                .with_client_cert_resolver(no_client_certificate())
        };
        let mut cfg = cfg;
        cfg.resumption = standard_session_resumption();
        // Apply ALPN
        cfg.alpn_protocols = profile.alpn_protocols.iter().map(|s| s.as_bytes().to_vec()).collect();
        if profile.enable_0rtt {
            return Err(ConnectionError::TlsError(
                "0-RTT is disabled until packet-level early-data keys are implemented".to_string(),
            ));
        }
        cfg.enable_early_data = false;
        cfg.enable_sni = true;
        // Create client connection with SNI
        let server_name_str = profile.sni.as_deref().unwrap_or(DEFAULT_TLS_SNI_HOST);
        let server_name = rustls::pki_types::ServerName::try_from(server_name_str)
            .map_err(|_| ConnectionError::TlsError("Invalid server name".into()))?
            .to_owned();
        self.connection = rustls::quic::Connection::Client(
            rustls::quic::ClientConnection::new(
                Arc::new(cfg),
                self.quic_version,
                server_name,
                self.transport_params.clone(),
            )
            .map_err(|e| ConnectionError::TlsError(format!("Client connection error: {}", e)))?,
        );
        // Drop CRYPTO bytes and key changes produced by the previous client connection.
        // The new connection has a new transcript and will emit a fresh ClientHello.
        self.crypto_initial.reset();
        self.crypto_handshake.reset();
        self.crypto_application.reset();
        self.pending_key_changes.clear();
        self.reset_packet_keys = true;
        self.next_1rtt_secrets = None;
        self.pending_local_1rtt.clear();
        self.pending_remote_1rtt.clear();
        self.handshake_complete = false;
        self.alpn = None;
        self.peer_cert = None;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.frame_buffer.clear();
        self.handshake_start = self.clock.now();
        Ok(())
    }
}

impl RustlsProviderImpl {
    fn ensure_1rtt_ready(
        &self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        if !self.handshake_complete || !installer.has_one_rtt_keys() {
            return Err(ConnectionError::TlsError(
                "key_update requires established 1-RTT keys".to_string(),
            ));
        }
        Ok(())
    }

    fn derive_next_1rtt_pair(&mut self) -> Result<(), ConnectionError> {
        let next = self.next_1rtt_secrets.as_mut().ok_or_else(|| {
            ConnectionError::TlsError(
                "key_update requires secret-based or rustls-provided update keys".to_string(),
            )
        })?;
        let keys = next.next_packet_keys();
        self.pending_local_1rtt.push_back(keys.local.into());
        self.pending_remote_1rtt.push_back(keys.remote.into());
        Ok(())
    }

    fn update_write_from_rustls_chain(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        if self.pending_local_1rtt.is_empty() {
            self.derive_next_1rtt_pair()?;
        }
        let Some(packet_key) = self.pending_local_1rtt.front().cloned() else {
            return Err(ConnectionError::TlsError(
                "missing local 1-RTT key update material".to_string(),
            ));
        };
        installer.rotate_1rtt_write_keypair(Box::new(RustlsPacketSeal { key: packet_key }))?;
        self.pending_local_1rtt.pop_front();
        Ok(())
    }

    fn update_read_from_rustls_chain(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        if self.pending_remote_1rtt.is_empty() {
            self.derive_next_1rtt_pair()?;
        }
        let Some(packet_key) = self.pending_remote_1rtt.front().cloned() else {
            return Err(ConnectionError::TlsError(
                "missing remote 1-RTT key update material".to_string(),
            ));
        };
        installer.rotate_1rtt_read_keypair(Box::new(RustlsPacketOpen { key: packet_key }))?;
        self.pending_remote_1rtt.pop_front();
        Ok(())
    }
}

struct RustlsPacketSeal {
    key: std::sync::Arc<dyn rustls::quic::PacketKey>,
}

impl crate::crypto::aead::AeadSeal for RustlsPacketSeal {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, ConnectionError> {
        #[cfg(test)]
        observe_standard_packet_operation(StandardPacketOperation::Seal);
        let tag_len = self.key.tag_len();
        if buf.len() < len + tag_len {
            return Err(ConnectionError::BufferTooShort);
        }
        let tag = self
            .key
            .encrypt_in_place(counter, ad, &mut buf[..len])
            .map_err(|e| ConnectionError::TlsError(format!("quic seal error: {}", e)))?;
        buf[len..len + tag_len].copy_from_slice(tag.as_ref());
        Ok(len + tag_len)
    }
}

struct RustlsPacketOpen {
    key: std::sync::Arc<dyn rustls::quic::PacketKey>,
}

impl crate::crypto::aead::AeadOpen for RustlsPacketOpen {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        #[cfg(test)]
        observe_standard_packet_operation(StandardPacketOperation::Open);
        let pt = self
            .key
            .decrypt_in_place(counter, ad, buf)
            .map_err(|e| ConnectionError::TlsError(format!("quic open error: {}", e)))?;
        Ok(pt.len())
    }
}

struct RustlsHp {
    key: std::sync::Arc<dyn rustls::quic::HeaderProtectionKey>,
}

impl crate::crypto::aead::PacketHeaderProtector for RustlsHp {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], ConnectionError> {
        let sample_len = self.key.sample_len();
        if sample.len() != sample_len {
            super::trace_hp_error(&format!(
                "hp sample length invalid have={} need={}",
                sample.len(),
                sample_len
            ));
            return Err(ConnectionError::CryptoError(format!(
                "header protection sample must be exactly {sample_len} bytes, got {}",
                sample.len()
            )));
        }

        // Derive the mask bytes by running HP on a controlled header snapshot.
        // We only need the low 5 bits of mask[0] (short header) and the next 4 bytes.
        // Force a 4-byte PN field in the HP helper call. Some implementations derive how many
        // PN bytes to mask from the low bits of `first`, so we set them to 3 (pn_len = 4).
        let first_orig: u8 = QUIC_FIXED_BIT | 0x03;
        let mut first: u8 = first_orig;
        let mut pn = [0u8; 4];
        if self.key.encrypt_in_place(sample, &mut first, &mut pn).is_err() {
            super::trace_hp_error("hp encrypt_in_place error");
            return Err(ConnectionError::CryptoError(
                "header protection mask derivation failed".into(),
            ));
        }
        let mask0 = first ^ first_orig;
        super::trace_hp_mask(mask0, pn);
        Ok([mask0, pn[0], pn[1], pn[2], pn[3]])
    }
}

impl super::QuicTlsProvider for RustlsProviderImpl {
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
        self.apply_profile_to_config(profile)
    }
    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError> {
        if let Some(ref mut profile) = self.profile {
            profile.sni = Some(name.to_string());
        }
        Ok(())
    }
    fn provide_quic_data(&mut self, _level: Level, data: &[u8]) -> Result<(), ConnectionError> {
        self.bytes_received += data.len();
        self.connection
            .read_hs(data)
            .map_err(|e| ConnectionError::TlsError(format!("Read handshake error: {}", e)))?;
        self.flush_handshake_io()?;
        Ok(())
    }
    fn next_crypto_frame(
        &mut self,
        level: Level,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        self.flush_handshake_io()?;
        self.crypto_stream_mut(level).next_crypto_frame(max_len)
    }
    fn ack_crypto(
        &mut self,
        level: Level,
        offset: u64,
        length: u64,
    ) -> Result<(), ConnectionError> {
        self.crypto_stream_mut(level).ack_crypto(offset, length)
    }
    fn requeue_crypto(
        &mut self,
        level: Level,
        offset: u64,
        length: u64,
    ) -> Result<(), ConnectionError> {
        self.crypto_stream_mut(level).requeue_crypto(offset, length)
    }
    fn requeue_all_crypto(&mut self, level: Level) {
        self.crypto_stream_mut(level).requeue_all_unacked();
    }
    fn has_pending_handshake_send(&self) -> bool {
        self.crypto_initial.has_pending_send() || self.crypto_handshake.has_pending_send()
    }
    fn poll_secrets_and_install(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.flush_handshake_io()?;
        if self.reset_packet_keys {
            installer.clear_handshake_and_one_rtt_keys();
            self.reset_packet_keys = false;
        }
        while let Some(change) = self.pending_key_changes.pop_front() {
            match change {
                PendingKeyChange::Handshake(keys) => installer.install_handshake_keys(keys),
                PendingKeyChange::OneRtt(keys) => {
                    installer.install_one_rtt_keys(keys);
                    self.pending_local_1rtt.clear();
                    self.pending_remote_1rtt.clear();
                }
            }
        }
        if self.peer_transport_params.is_none() {
            self.peer_transport_params =
                self.connection.quic_transport_parameters().map(<[u8]>::to_vec);
        }
        let have_1rtt = installer.has_one_rtt_keys();
        if !self.handshake_complete && !self.connection.is_handshaking() && have_1rtt {
            self.handshake_complete = true;
            let duration = self.clock.elapsed_since(self.handshake_start);
            let negotiated = self
                .connection
                .negotiated_cipher_suite()
                .ok_or_else(|| {
                    ConnectionError::TlsError(
                        "completed rustls handshake has no negotiated cipher suite".to_string(),
                    )
                })
                .and_then(|suite| standard_cipher_suite(suite.suite()))?;
            log::info!(
                "TLS handshake complete in {:?} with QUIC {:?}, suite={}, packet_owner=rustls-standard, header_owner=rustls-standard",
                duration,
                self.quic_version,
                negotiated.as_str()
            );
            if let Some(alpn) = self.connection.alpn_protocol() {
                self.alpn = Some(String::from_utf8_lossy(alpn).to_string());
            }
            if let Some(certs) = self.connection.peer_certificates() {
                if let Some(cert) = certs.first() {
                    self.peer_cert = Some(cert.to_vec());
                }
            }
        }
        Ok(())
    }
    fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }
    fn handshake_resumed(&self) -> bool {
        self.handshake_complete
            && self.connection.handshake_kind() == Some(rustls::HandshakeKind::Resumed)
    }
    fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }
    fn peer_cert(&self) -> Option<Vec<u8>> {
        self.peer_cert.clone()
    }
    fn server_name_get(&self) -> Option<&str> {
        // Server name stored in profile.sni
        self.profile.as_ref().and_then(|p| p.sni.as_deref())
    }
    fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>> {
        // Rustls keeps opaque tickets inside its ClientSessionStore and does not
        // expose their bytes. Returning a digest here would be misleading and
        // could be mistaken for proof of resumption. Use handshake_resumed().
        None
    }
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError> {
        self.zero_rtt_enabled = false;
        Err(ConnectionError::TlsError(
            "0-RTT is disabled until packet-level early-data keys are implemented".to_string(),
        ))
    }
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<SensitiveKeyingMaterial, ConnectionError> {
        if length == 0 {
            return Err(ConnectionError::TlsError(
                "export_keying_material requires non-zero length".to_string(),
            ));
        }
        let output = SensitiveKeyingMaterial::new(vec![0u8; length]);
        self.connection
            .export_keying_material(
                output,
                label,
                if context.is_empty() { None } else { Some(context) },
            )
            .map_err(|e| ConnectionError::TlsError(format!("export_keying_material failed: {}", e)))
    }
    fn get_quic_transport_params(&self) -> Vec<u8> {
        self.transport_params.clone()
    }
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError> {
        self.peer_transport_params = Some(params.to_vec());
        Ok(())
    }
    fn peer_quic_transport_params(&self) -> Option<Vec<u8>> {
        self.peer_transport_params.clone()
    }
    fn key_update(&mut self, installer: &dyn QuicTlsKeyInstaller) -> Result<(), ConnectionError> {
        self.key_update_write(installer)?;
        self.key_update_read(installer)
    }
    fn key_update_read(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.ensure_1rtt_ready(installer)?;
        if installer.key_update_1rtt_read()? {
            return Ok(());
        }
        self.update_read_from_rustls_chain(installer)
    }
    fn key_update_write(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.ensure_1rtt_ready(installer)?;
        if installer.key_update_1rtt_write()? {
            return Ok(());
        }
        self.update_write_from_rustls_chain(installer)
    }
    fn provider_name(&self) -> &str {
        "rustls"
    }
    fn supports_ch_override(&self) -> bool {
        false
    }
}

#[allow(dead_code)]
pub(super) fn make_with_ca_with_snapshot(
    is_server: bool,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    client_ca_path: Option<&str>,
    environment: &crate::env_utils::EnvSnapshot,
) -> Result<RustlsProviderImpl, ConnectionError> {
    RustlsProviderImpl::new_with_ca_with_snapshot_and_clock(
        is_server,
        verify_peer,
        version,
        version_information_parameter,
        client_ca_path,
        environment,
        &crate::time_source::ProtocolClock::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn make_with_ca_with_snapshot_and_clock_and_max_udp_payload(
    is_server: bool,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    client_ca_path: Option<&str>,
    environment: &crate::env_utils::EnvSnapshot,
    clock: &crate::time_source::ProtocolClock,
    max_udp_payload_size: usize,
) -> Result<RustlsProviderImpl, ConnectionError> {
    RustlsProviderImpl::new_with_ca_with_snapshot_and_clock_and_max_udp_payload(
        is_server,
        verify_peer,
        version,
        version_information_parameter,
        client_ca_path,
        environment,
        clock,
        max_udp_payload_size,
    )
}
