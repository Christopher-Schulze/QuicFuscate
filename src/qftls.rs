#![allow(unexpected_cfgs)]
// Unified TLS stack for QuicFuscate
// Consolidates: tls_provider.rs, tls_combined.rs, RealTLS_rustls.rs
// Provides a single public surface: Level, TlsProfile, QuicTlsProvider, create_provider()

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
#[cfg(unix)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::error::ConnectionError;
use qf_transport_types::QUIC_FIXED_BIT;
#[cfg(test)]
use qf_transport_version::VersionInformation;
use qf_transport_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_V2};

mod tls_cover_provider;

pub(crate) use tls_cover_provider::TlsCoverProvider;

/// Compatibility export for the root TLS namespace. The canonical contract lives in the
/// dependency-free transport-types leaf.
pub use qf_transport_types::QuicEncryptionLevel as Level;

/// Sensitive keying material returned by the TLS exporter.
pub type SensitiveKeyingMaterial = Zeroizing<Vec<u8>>;

/// Historical TLS name for the canonical individual memory-lock status.
pub use qf_memory_lock::MemoryLockAllocationStatus as TlsKeyLockStatus;

static TLS_CERT_PATH_OVERRIDE: OnceLock<String> = OnceLock::new();
static TLS_KEY_PATH_OVERRIDE: OnceLock<String> = OnceLock::new();
static TLS_SERVER_IDENTITY_OVERRIDE: OnceLock<PreloadedServerIdentity> = OnceLock::new();
static TLS_OVERRIDE_REQUIRED: AtomicBool = AtomicBool::new(false);
/// Configurable max early data size for server TLS config.
/// RFC 9001 §4.6.1: QUIC requires this to be either 0 (no 0-RTT) or 0xFFFF_FFFF (0-RTT enabled).
/// Default is u32::MAX (0-RTT offered). Set to 0 to disable 0-RTT.
/// Set via `set_max_early_data_size()` before server connection creation.
static MAX_EARLY_DATA_SIZE: AtomicU32 = AtomicU32::new(u32::MAX);

/// Reports the result of publishing a preloaded server identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsIdentityPreloadStatus {
    /// This call published the process-lifetime identity owner.
    Loaded { key_lock: TlsKeyLockStatus },
    /// The exact same certificate and key were already published.
    AlreadyLoaded,
}

enum KeyMaterialStorage {
    Heap(Zeroizing<Vec<u8>>),
    #[cfg(unix)]
    Mapped(MappedKeyMaterial),
}

impl KeyMaterialStorage {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Heap(bytes) => bytes.as_slice(),
            #[cfg(unix)]
            Self::Mapped(bytes) => bytes.as_slice(),
        }
    }
}

struct LockedKeyMaterial {
    storage: KeyMaterialStorage,
    status: TlsKeyLockStatus,
}

impl LockedKeyMaterial {
    fn new(bytes: Zeroizing<Vec<u8>>, lock_memory: bool) -> Self {
        let (storage, status) = if !lock_memory {
            (KeyMaterialStorage::Heap(bytes), TlsKeyLockStatus::Disabled)
        } else if qf_memory_lock::process_memory_lock_covers_future_allocations() {
            (KeyMaterialStorage::Heap(bytes), TlsKeyLockStatus::CoveredByProcess)
        } else {
            Self::individually_locked_storage(bytes)
        };
        Self { storage, status }
    }

    #[cfg(unix)]
    fn individually_locked_storage(
        bytes: Zeroizing<Vec<u8>>,
    ) -> (KeyMaterialStorage, TlsKeyLockStatus) {
        match MappedKeyMaterial::new(bytes) {
            Ok(mapped) => {
                let status = mapped.status();
                (KeyMaterialStorage::Mapped(mapped), status)
            }
            Err((bytes, error)) => {
                log::warn!("Failed to allocate page-exclusive TLS private-key memory: {error}");
                (KeyMaterialStorage::Heap(bytes), TlsKeyLockStatus::Unavailable)
            }
        }
    }

    #[cfg(not(unix))]
    fn individually_locked_storage(
        bytes: Zeroizing<Vec<u8>>,
    ) -> (KeyMaterialStorage, TlsKeyLockStatus) {
        log::debug!("Individual TLS private-key memory locking is unsupported on this platform");
        (KeyMaterialStorage::Heap(bytes), TlsKeyLockStatus::Unavailable)
    }

    fn as_slice(&self) -> &[u8] {
        self.storage.as_slice()
    }

    fn status(&self) -> TlsKeyLockStatus {
        self.status
    }
}

#[cfg(unix)]
struct MappedKeyMaterial {
    ptr: *mut u8,
    len: usize,
    status: TlsKeyLockStatus,
}

#[cfg(unix)]
impl MappedKeyMaterial {
    fn new(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, (Zeroizing<Vec<u8>>, std::io::Error)> {
        if bytes.is_empty() {
            return Err((
                bytes,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TLS private-key bytes must not be empty",
                ),
            ));
        }

        // SAFETY: the anonymous private mapping has a non-zero length, no file
        // descriptor owner, and no caller-provided address. MAP_FAILED is handled
        // before the returned pointer is used.
        let len = bytes.len();
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err((bytes, std::io::Error::last_os_error()));
        }

        let ptr = mapping.cast::<u8>();
        // SAFETY: mmap returned a live writable mapping of at least bytes.len()
        // bytes, and the source allocation is distinct and live for the copy.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len) };
        bytes.zeroize();

        let mut mapped = Self { ptr, len, status: TlsKeyLockStatus::Unavailable };
        mapped.status = try_lock_key_material(mapped.as_slice());
        Ok(mapped)
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr and len identify the live mapping exclusively owned by self.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn status(&self) -> TlsKeyLockStatus {
        self.status
    }
}

// SAFETY: the mapping is exclusively owned by this value. It exposes only
// immutable slices, and destruction requires exclusive access to the owner.
#[cfg(unix)]
unsafe impl Send for MappedKeyMaterial {}
// SAFETY: shared access exposes immutable bytes only; mutation occurs solely
// during Drop after exclusive ownership has been established.
#[cfg(unix)]
unsafe impl Sync for MappedKeyMaterial {}

#[cfg(unix)]
impl Drop for MappedKeyMaterial {
    fn drop(&mut self) {
        // SAFETY: ptr and len still identify this owner's live writable mapping.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }.zeroize();
        if self.status == TlsKeyLockStatus::Locked {
            let _ = unlock_key_material(self.ptr, self.len);
        }
        // SAFETY: ptr and len are the exact mapping returned by mmap and have
        // not been unmapped previously.
        if unsafe { libc::munmap(self.ptr.cast(), self.len) } != 0 {
            log::error!(
                "Failed to unmap preloaded TLS private-key memory ({} bytes): {}",
                self.len,
                std::io::Error::last_os_error()
            );
        }
    }
}

struct PreloadedServerIdentity {
    cert_pem: Vec<u8>,
    key_pem: LockedKeyMaterial,
}

impl PreloadedServerIdentity {
    fn new(cert_pem: Vec<u8>, key_pem: Zeroizing<Vec<u8>>, lock_memory: bool) -> Self {
        Self { cert_pem, key_pem: LockedKeyMaterial::new(key_pem, lock_memory) }
    }

    fn matches(&self, cert_pem: &[u8], key_pem: &[u8]) -> bool {
        self.cert_pem == cert_pem && self.key_pem.as_slice() == key_pem
    }
}

#[cfg(unix)]
fn try_lock_key_material(bytes: &[u8]) -> TlsKeyLockStatus {
    // SAFETY: `bytes` is a live allocation owned by `LockedKeyMaterial` for the
    // complete duration of the syscall and has the exact length passed here.
    if unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) } == 0 {
        TlsKeyLockStatus::Locked
    } else {
        let error = std::io::Error::last_os_error();
        log::warn!("Failed to lock preloaded TLS private key in memory: {error}");
        TlsKeyLockStatus::Unavailable
    }
}

#[cfg(unix)]
fn unlock_key_material(ptr: *const u8, len: usize) -> bool {
    // SAFETY: the pointer and length are the exact allocation range previously
    // locked by this guard, and the allocation remains alive during the call.
    #[cfg(test)]
    // SAFETY: the caller guarantees the mapping remains live for this call.
    let zeroized = unsafe { std::slice::from_raw_parts(ptr, len) }.iter().all(|byte| *byte == 0);
    let unlocked = unsafe { libc::munlock(ptr.cast(), len) } == 0;
    #[cfg(test)]
    KEY_UNLOCK_OBSERVATIONS.with(|observations| {
        observations.borrow_mut().push((zeroized, unlocked));
    });
    if !unlocked {
        log::error!(
            "Failed to unlock preloaded TLS private-key memory ({} bytes): {}",
            len,
            std::io::Error::last_os_error()
        );
    }
    unlocked
}

#[cfg(all(unix, test))]
thread_local! {
    static KEY_UNLOCK_OBSERVATIONS: std::cell::RefCell<Vec<(bool, bool)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(all(unix, test))]
fn take_key_unlock_observations() -> Vec<(bool, bool)> {
    KEY_UNLOCK_OBSERVATIONS.with(|observations| std::mem::take(&mut *observations.borrow_mut()))
}

/// Tell the qftls owner whether process-wide locking covers future allocations.
///
/// Standalone startup calls this only after a successful
/// `mlockall(MCL_CURRENT | MCL_FUTURE)` operation. `MCL_CURRENT` alone is not
/// sufficient because a later TLS key allocation still needs its own lock.
#[doc(hidden)]
pub fn set_process_memory_lock_covers_future_allocations(enabled: bool) {
    qf_memory_lock::set_process_memory_lock_covers_future_allocations(enabled);
}

fn publish_preloaded_identity(
    slot: &OnceLock<PreloadedServerIdentity>,
    identity: PreloadedServerIdentity,
) -> Result<TlsIdentityPreloadStatus, ConnectionError> {
    let key_lock = identity.key_pem.status();
    match slot.set(identity) {
        Ok(()) => Ok(TlsIdentityPreloadStatus::Loaded { key_lock }),
        Err(rejected) => {
            let same_identity = slot.get().is_some_and(|existing| {
                existing.matches(&rejected.cert_pem, rejected.key_pem.as_slice())
            });
            drop(rejected);
            if same_identity {
                Ok(TlsIdentityPreloadStatus::AlreadyLoaded)
            } else {
                Err(ConnectionError::TlsError(
                    "TLS server identity already preloaded with a different certificate or private key"
                        .to_string(),
                ))
            }
        }
    }
}

/// Set the maximum early data size for new server TLS connections.
pub fn set_max_early_data_size(size: u32) {
    MAX_EARLY_DATA_SIZE.store(size, Ordering::Relaxed);
}
const DEFAULT_TLS_SNI_HOST: &str = "cdn.cloudflare.com";

fn trace_key_change(is_server: bool, label: &str) {
    log::trace!("[qftls] {:?} keychange={}", if is_server { "server" } else { "client" }, label);
}

fn trace_hp_error(message: &str) {
    log::trace!("[qftls] {}", message);
}

fn trace_hp_mask(mask0: u8, pn: [u8; 4]) {
    log::trace!(
        "[qftls] hp mask0={:02x} pn={:02x}{:02x}{:02x}{:02x}",
        mask0,
        pn[0],
        pn[1],
        pn[2],
        pn[3]
    );
}

/// Override the TLS certificate and private key file paths for server mode.
pub fn set_tls_cert_key_paths(cert_path: &str, key_path: &str) {
    if TLS_CERT_PATH_OVERRIDE.set(cert_path.to_string()).is_err() {
        log::debug!("TLS cert path override already set, keeping existing value");
    }
    if TLS_KEY_PATH_OVERRIDE.set(key_path.to_string()).is_err() {
        log::debug!("TLS key path override already set, keeping existing value");
    }
    TLS_OVERRIDE_REQUIRED.store(true, Ordering::SeqCst);
}

/// Read and validate the server identity before privileged initialization ends.
///
/// New server connections use this in-memory copy instead of reopening a
/// root-owned private-key file after the process drops to its runtime UID.
///
/// `lock_memory` is the canonical security policy for the individual key
/// buffer. Lock failure is best-effort for compatibility with finite
/// `RLIMIT_MEMLOCK`; the returned status and startup warning make degradation
/// observable. The accepted identity is process-lifetime-owned by the static
/// `OnceLock`; rejected duplicate/conflicting values are dropped through the
/// exact-range guard and therefore unlock their own successful `mlock` call.
pub fn preload_tls_server_identity(
    cert_path: &str,
    key_path: &str,
    lock_memory: bool,
) -> Result<TlsIdentityPreloadStatus, ConnectionError> {
    let cert_pem = std::fs::read(cert_path).map_err(|error| {
        ConnectionError::TlsError(format!("Cert read failed ({cert_path}): {error}"))
    })?;
    let key_pem = Zeroizing::new(std::fs::read(key_path).map_err(|error| {
        ConnectionError::TlsError(format!("Key read failed ({key_path}): {error}"))
    })?);
    rustls_provider::validate_server_identity_pem(&cert_pem, key_pem.as_slice())?;

    if let Some(existing) = TLS_SERVER_IDENTITY_OVERRIDE.get() {
        if existing.matches(&cert_pem, key_pem.as_slice()) {
            return Ok(TlsIdentityPreloadStatus::AlreadyLoaded);
        }
        return Err(ConnectionError::TlsError(
            "TLS server identity already preloaded with a different certificate or private key"
                .to_string(),
        ));
    }

    let identity = PreloadedServerIdentity::new(cert_pem, key_pem, lock_memory);
    let status = publish_preloaded_identity(&TLS_SERVER_IDENTITY_OVERRIDE, identity)?;
    if matches!(status, TlsIdentityPreloadStatus::Loaded { .. }) {
        set_tls_cert_key_paths(cert_path, key_path);
    }
    Ok(status)
}

// ===============================
// Core Types and Trait
// ===============================

/// Browser-shaped TLS profile contract and fingerprint conversion owned by qf-stealth.
pub use qf_stealth::{profile_from_fingerprint, TlsProfile};

#[cfg(test)]
mod tests;

/// TLS Provider abstraction used by transport.
///
/// The actual protocol TLS engine is always rustls.
/// Optional TLS cover behavior is composed on top of it.
pub struct QuicTlsHandshakeKeys {
    /// Local packet sealer.
    pub seal: Box<dyn qf_crypto::aead::AeadSeal + Send + Sync>,
    /// Remote packet opener.
    pub open: Box<dyn qf_crypto::aead::AeadOpen + Send + Sync>,
    /// Local header-protection key.
    pub hp_seal: Box<dyn qf_crypto::aead::PacketHeaderProtector + Send + Sync>,
    /// Remote header-protection key.
    pub hp_open: Box<dyn qf_crypto::aead::PacketHeaderProtector + Send + Sync>,
}

/// Directional 1-RTT packet-protection keys emitted by the TLS owner.
pub struct QuicTlsOneRttKeys {
    /// Local packet sealer.
    pub seal: Arc<qf_crypto::PacketAeadSeal>,
    /// Remote packet opener.
    pub open: Arc<qf_crypto::PacketAeadOpen>,
    /// Local header-protection key.
    pub hp_seal: Arc<dyn qf_crypto::aead::PacketHeaderProtector + Send + Sync>,
    /// Remote header-protection key.
    pub hp_open: Arc<dyn qf_crypto::aead::PacketHeaderProtector + Send + Sync>,
}

/// Transport-owned packet-key installation port consumed by the TLS provider.
pub trait QuicTlsKeyInstaller: Send + Sync {
    /// Clear Handshake and 1-RTT keys after a TLS transcript rebuild.
    fn clear_handshake_and_one_rtt_keys(&self);
    /// Replace the directional Handshake packet keys atomically under the transport lock.
    fn install_handshake_keys(&self, keys: QuicTlsHandshakeKeys);
    /// Replace the directional 1-RTT packet keys atomically under the transport lock.
    fn install_one_rtt_keys(&self, keys: QuicTlsOneRttKeys);
    /// Return whether both directional 1-RTT packet keys are installed.
    fn has_one_rtt_keys(&self) -> bool;
    /// Attempt a transport-secret-backed read-key update.
    fn key_update_1rtt_read(&self) -> Result<bool, ConnectionError>;
    /// Attempt a transport-secret-backed write-key update.
    fn key_update_1rtt_write(&self) -> Result<bool, ConnectionError>;
    /// Install the next rustls-provided read key.
    fn rotate_1rtt_read_keypair(&self, open: Box<dyn qf_crypto::aead::AeadOpen + Send + Sync>);
    /// Install the next rustls-provided write key.
    fn rotate_1rtt_write_keypair(&self, seal: Box<dyn qf_crypto::aead::AeadSeal + Send + Sync>);
}

pub trait QuicTlsProvider: Send + Sync {
    /// Configure with profile
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError>;
    /// Set server name for SNI
    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError>;
    /// Provide incoming CRYPTO frame data
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError>;
    /// Get next outgoing CRYPTO frame
    fn next_crypto_frame(
        &mut self,
        level: Level,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError>;
    /// Retire an acknowledged CRYPTO range at the selected encryption level.
    fn ack_crypto(&mut self, level: Level, offset: u64, length: u64)
        -> Result<(), ConnectionError>;
    /// Requeue a lost CRYPTO range at the selected encryption level.
    fn requeue_crypto(
        &mut self,
        level: Level,
        offset: u64,
        length: u64,
    ) -> Result<(), ConnectionError>;
    /// Requeue every retained CRYPTO range for a PTO probe.
    fn requeue_all_crypto(&mut self, level: Level);
    /// Return whether an Initial or Handshake flight still has unsent bytes.
    fn has_pending_handshake_send(&self) -> bool;
    /// Poll for new secrets and install them
    fn poll_secrets_and_install(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError>;
    /// Check if handshake is complete
    fn handshake_complete(&self) -> bool;
    /// Get negotiated ALPN protocol
    fn alpn(&self) -> Option<&str>;
    /// Get peer certificate (if any)
    fn peer_cert(&self) -> Option<Vec<u8>>;
    /// Get peer certificate chain (if any) - full chain DER encoded
    fn peer_cert_chain(&self) -> Option<Vec<Vec<u8>>> {
        // Default: return just the leaf cert if available
        self.peer_cert().map(|c| vec![c])
    }
    /// Get configured server name (SNI)
    fn server_name_get(&self) -> Option<&str>;
    /// Get TLS session ticket for resumption (if any)
    fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>>;
    /// Enable 0-RTT if supported
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError>;
    /// Get 0-RTT keys if available
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)>;
    /// Export keying material (for QUIC key update) with an erasing owner.
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<SensitiveKeyingMaterial, ConnectionError>;
    /// Get transport parameters to send
    fn get_quic_transport_params(&self) -> Vec<u8>;
    /// Set peer's transport parameters
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError>;
    /// Returns authenticated peer transport parameters once rustls exposes them.
    fn peer_quic_transport_params(&self) -> Option<Vec<u8>>;
    /// Initiate key update
    fn key_update(&mut self, installer: &dyn QuicTlsKeyInstaller) -> Result<(), ConnectionError>;
    /// Advance read-side 1-RTT keys only.
    fn key_update_read(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.key_update(installer)
    }
    /// Advance write-side 1-RTT keys only.
    fn key_update_write(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.key_update(installer)
    }
    /// Get provider name (for debugging)
    fn provider_name(&self) -> &str;
    /// Check if provider supports ClientHello override through cover/mimicry layer.
    fn supports_ch_override(&self) -> bool;
    /// Apply ClientHello override (if supported)
    fn apply_ch_override(&mut self, _template: &[u8]) -> Result<(), ConnectionError> {
        if !self.supports_ch_override() {
            return Err(ConnectionError::TlsError("Provider doesn't support CH override".into()));
        }
        Ok(())
    }
}

/// Create the canonical TLS provider.
///
/// This always returns the real rustls transport owner with optional cover-layer composition.
pub fn create_provider(is_server: bool) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_with_peer_verification(is_server, true)
}

pub(crate) fn create_provider_with_peer_verification(
    is_server: bool,
    verify_peer: bool,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_for_version(is_server, verify_peer, PROTOCOL_VERSION, &[])
}

pub(crate) fn create_provider_for_version(
    is_server: bool,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_for_version_with_ca(
        is_server,
        verify_peer,
        version,
        version_information_parameter,
        None,
    )
}

pub(crate) fn create_provider_for_version_with_ca(
    is_server: bool,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    verify_locations_file: Option<&str>,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    let environment = crate::env_utils::EnvSnapshot::capture();
    create_provider_for_version_with_ca_with_snapshot(
        is_server,
        verify_peer,
        version,
        version_information_parameter,
        verify_locations_file,
        &environment,
    )
}

pub(crate) fn create_provider_for_version_with_ca_with_snapshot(
    is_server: bool,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    verify_locations_file: Option<&str>,
    environment: &crate::env_utils::EnvSnapshot,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    create_provider_for_version_with_ca_with_snapshot_and_clock(
        is_server,
        verify_peer,
        version,
        version_information_parameter,
        verify_locations_file,
        environment,
        &crate::time_source::ProtocolClock::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_provider_for_version_with_ca_with_snapshot_and_clock(
    is_server: bool,
    verify_peer: bool,
    version: u32,
    version_information_parameter: &[u8],
    verify_locations_file: Option<&str>,
    environment: &crate::env_utils::EnvSnapshot,
    clock: &crate::time_source::ProtocolClock,
) -> Result<Box<dyn QuicTlsProvider>, ConnectionError> {
    Ok(Box::new(CombinedProvider::new_with_ca_with_snapshot_and_clock(
        is_server,
        verify_peer,
        version,
        version_information_parameter,
        verify_locations_file,
        environment,
        clock,
    )?))
}

// ===============================
// Combined Provider (rustls + optional TLS Cover)
// rustls remains the TLS protocol owner; cover is an overlay only.
// ===============================

/// Combined TLS provider composing rustls (protocol owner) with an optional TLS cover overlay.
pub struct CombinedProvider {
    rustls: RustlsProvider,
    cover: Option<TlsCoverProvider>,
}

impl CombinedProvider {
    fn env_string(
        environment: &crate::env_utils::EnvSnapshot,
        name: &str,
        default: &str,
    ) -> String {
        environment.first([name]).unwrap_or_else(|| default.to_string())
    }

    /// Create a new combined provider (rustls + optional TLS cover).
    pub fn new(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca(is_server, verify_peer, version, version_information_parameter, None)
    }

    fn new_with_ca(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        verify_locations_file: Option<&str>,
    ) -> Result<Self, ConnectionError> {
        let environment = crate::env_utils::EnvSnapshot::capture();
        Self::new_with_ca_with_snapshot(
            is_server,
            verify_peer,
            version,
            version_information_parameter,
            verify_locations_file,
            &environment,
        )
    }

    fn new_with_ca_with_snapshot(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        verify_locations_file: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca_with_snapshot_and_clock(
            is_server,
            verify_peer,
            version,
            version_information_parameter,
            verify_locations_file,
            environment,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_ca_with_snapshot_and_clock(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        verify_locations_file: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<Self, ConnectionError> {
        let rustls = RustlsProvider::new_with_ca_with_snapshot_and_clock(
            is_server,
            verify_peer,
            version,
            version_information_parameter,
            verify_locations_file,
            environment,
            clock,
        )?;
        // Cover is optional and intentionally separated from TLS protocol semantics.
        // It can be disabled via ENV QUICFUSCATE_TLS_COVER=0.
        // In base/performance mode, cover keeps traffic shape with reduced timing overhead.
        let cover_enabled = environment.flag("QUICFUSCATE_TLS_COVER", true);
        let cover = if cover_enabled {
            // Check stealth mode to determine TLS Cover behavior
            let stealth_mode = Self::env_string(environment, "QUICFUSCATE_STEALTH_MODE", "stealth");

            let mut tls_cover = TlsCoverProvider::new_with_snapshot(is_server, environment)?;

            // In base/performance mode, TLS Cover still runs but without artificial delays
            if stealth_mode == "base" || stealth_mode == "performance" || stealth_mode == "off" {
                tls_cover.set_performance_mode(true);
                log::info!("TLS Cover enabled in performance mode: full cover traffic, no delays");
            } else {
                log::info!(
                    "TLS Cover enabled in stealth mode: full sophistication with timing/padding"
                );
            }

            // Enable profile rotation if requested
            if environment.flag("QUICFUSCATE_TLS_COVER_ROTATE", false) {
                log::info!("TLS Cover profile rotation enabled");
            }

            // Enable telemetry if requested
            if environment.flag("QUICFUSCATE_TLS_COVER_TELEMETRY", false) {
                log::info!("TLS Cover telemetry enabled");
            }

            Some(tls_cover)
        } else {
            None
        };
        // Telemetry: 0 = rustls-only, 1 = rustls+tls-cover
        let kind = if cover.is_some() { 1 } else { 0 };
        crate::optimize::telemetry::TLS_PROVIDER_KIND.set(kind);
        Ok(Self { rustls, cover })
    }
}

impl QuicTlsProvider for CombinedProvider {
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
        // Configure rustls first (protocol semantics).
        self.rustls.configure(profile)?;
        // Apply session hint (ALPN/SNI bias) if available.
        self.rustls.apply_session_hint_to_profile();
        // Apply optional cover layer configuration.
        if let Some(ref mut c) = self.cover {
            c.set_performance_mode(profile.cover_performance_mode);
        }
        Ok(())
    }

    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError> {
        self.rustls.set_server_name(name)?;
        Ok(())
    }

    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError> {
        if let Some(ref mut c) = self.cover {
            if let Err(e) = c.provide_quic_data(level, data) {
                log::debug!("TLS cover provider rejected QUIC data at level {:?}: {}", level, e);
            }
        }
        self.rustls.provide_quic_data(level, data)
    }

    fn next_crypto_frame(
        &mut self,
        level: Level,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        // rustls-driven handshake frames always take priority.
        if let Some(frame) = self.rustls.next_crypto_frame(level, max_len)? {
            return Ok(Some(frame));
        }
        // Emit optional cover decoy frames before real handshake completion.
        if let Some(ref mut c) = self.cover {
            if !self.rustls.handshake_complete() {
                return c.next_crypto_frame(level, max_len);
            }
        }
        Ok(None)
    }

    fn ack_crypto(
        &mut self,
        level: Level,
        offset: u64,
        length: u64,
    ) -> Result<(), ConnectionError> {
        self.rustls.ack_crypto(level, offset, length)
    }

    fn requeue_crypto(
        &mut self,
        level: Level,
        offset: u64,
        length: u64,
    ) -> Result<(), ConnectionError> {
        self.rustls.requeue_crypto(level, offset, length)
    }

    fn requeue_all_crypto(&mut self, level: Level) {
        self.rustls.requeue_all_crypto(level);
    }

    fn has_pending_handshake_send(&self) -> bool {
        self.rustls.has_pending_handshake_send()
    }

    fn poll_secrets_and_install(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        if let Some(ref mut c) = self.cover {
            if let Err(e) = c.poll_secrets_and_install() {
                log::debug!("TLS cover provider secret poll/install failed: {}", e);
            }
        }
        self.rustls.poll_secrets_and_install(installer)
    }

    fn handshake_complete(&self) -> bool {
        self.rustls.handshake_complete()
    }
    fn alpn(&self) -> Option<&str> {
        self.rustls.alpn()
    }
    fn peer_cert(&self) -> Option<Vec<u8>> {
        self.rustls.peer_cert()
    }
    fn server_name_get(&self) -> Option<&str> {
        self.rustls.server_name_get()
    }
    fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.rustls.session_ticket()
    }
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError> {
        self.rustls.enable_0rtt()
    }
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.rustls.get_0rtt_keys()
    }
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<SensitiveKeyingMaterial, ConnectionError> {
        self.rustls.export_keying_material(label, context, length)
    }
    fn get_quic_transport_params(&self) -> Vec<u8> {
        self.rustls.get_quic_transport_params()
    }
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError> {
        self.rustls.set_peer_transport_params(params)
    }
    fn peer_quic_transport_params(&self) -> Option<Vec<u8>> {
        self.rustls.peer_quic_transport_params()
    }
    fn key_update(&mut self, installer: &dyn QuicTlsKeyInstaller) -> Result<(), ConnectionError> {
        self.rustls.key_update(installer)
    }
    fn key_update_read(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.rustls.key_update_read(installer)
    }
    fn key_update_write(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.rustls.key_update_write(installer)
    }
    fn provider_name(&self) -> &str {
        if self.cover.is_some() {
            "rustls+tls-cover"
        } else {
            "rustls"
        }
    }
    fn supports_ch_override(&self) -> bool {
        // TLS Cover emits synthetic decoy records only; rustls owns the real ClientHello.
        false
    }
}

// ===============================
// Native rustls 0.23 QUIC provider
// ===============================

mod rustls_provider;

/// Thin wrapper around the rustls QUIC provider implementing `QuicTlsProvider`.
pub struct RustlsProvider(rustls_provider::RustlsProviderImpl);

impl RustlsProvider {
    /// Create a new rustls-backed TLS provider for client or server mode.
    pub fn new(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
    ) -> Result<Self, ConnectionError> {
        Self::new_with_ca(is_server, verify_peer, version, version_information_parameter, None)
    }

    fn new_with_ca(
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

    fn new_with_ca_with_snapshot(
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
    fn new_with_ca_with_snapshot_and_clock(
        is_server: bool,
        verify_peer: bool,
        version: u32,
        version_information_parameter: &[u8],
        client_ca_path: Option<&str>,
        environment: &crate::env_utils::EnvSnapshot,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<Self, ConnectionError> {
        Ok(Self(rustls_provider::make_with_ca_with_snapshot_and_clock(
            is_server,
            verify_peer,
            version,
            version_information_parameter,
            client_ca_path,
            environment,
            clock,
        )?))
    }
}

impl QuicTlsProvider for RustlsProvider {
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError> {
        self.0.configure(profile)
    }
    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError> {
        self.0.set_server_name(name)
    }
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError> {
        self.0.provide_quic_data(level, data)
    }
    fn next_crypto_frame(
        &mut self,
        level: Level,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        self.0.next_crypto_frame(level, max_len)
    }
    fn ack_crypto(
        &mut self,
        level: Level,
        offset: u64,
        length: u64,
    ) -> Result<(), ConnectionError> {
        self.0.ack_crypto(level, offset, length)
    }
    fn requeue_crypto(
        &mut self,
        level: Level,
        offset: u64,
        length: u64,
    ) -> Result<(), ConnectionError> {
        self.0.requeue_crypto(level, offset, length)
    }
    fn requeue_all_crypto(&mut self, level: Level) {
        self.0.requeue_all_crypto(level);
    }
    fn has_pending_handshake_send(&self) -> bool {
        self.0.has_pending_handshake_send()
    }
    fn poll_secrets_and_install(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.0.poll_secrets_and_install(installer)
    }
    fn handshake_complete(&self) -> bool {
        self.0.handshake_complete()
    }
    fn alpn(&self) -> Option<&str> {
        self.0.alpn()
    }
    fn peer_cert(&self) -> Option<Vec<u8>> {
        self.0.peer_cert()
    }
    fn server_name_get(&self) -> Option<&str> {
        self.0.server_name_get()
    }
    fn session_ticket(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.0.session_ticket()
    }
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError> {
        self.0.enable_0rtt()
    }
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        self.0.get_0rtt_keys()
    }
    fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<SensitiveKeyingMaterial, ConnectionError> {
        self.0.export_keying_material(label, context, length)
    }
    fn get_quic_transport_params(&self) -> Vec<u8> {
        self.0.get_quic_transport_params()
    }
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError> {
        self.0.set_peer_transport_params(params)
    }
    fn peer_quic_transport_params(&self) -> Option<Vec<u8>> {
        self.0.peer_quic_transport_params()
    }
    fn key_update(&mut self, installer: &dyn QuicTlsKeyInstaller) -> Result<(), ConnectionError> {
        self.0.key_update(installer)
    }
    fn key_update_read(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.0.key_update_read(installer)
    }
    fn key_update_write(
        &mut self,
        installer: &dyn QuicTlsKeyInstaller,
    ) -> Result<(), ConnectionError> {
        self.0.key_update_write(installer)
    }
    fn provider_name(&self) -> &str {
        self.0.provider_name()
    }
    fn supports_ch_override(&self) -> bool {
        self.0.supports_ch_override()
    }
}

impl RustlsProvider {
    pub fn apply_session_hint_to_profile(&mut self) {
        if self.0.session_cache.is_some() {
            if let Some(ref mut prof) = self.0.profile {
                if !prof.alpn_protocols.is_empty() && prof.alpn_protocols[0] != "h3" {
                    prof.alpn_protocols.retain(|p| p != "h3");
                    prof.alpn_protocols.insert(0, "h3".into());
                }
            }
        }
    }
}

// BoringSSL/RealTLS code was removed from src and centralized in archive/boringisland.rs.
