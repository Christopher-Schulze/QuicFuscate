#![allow(unexpected_cfgs)]
//! # Crypto Module
//!
//! Packet crypto. The ship default is rustls/ring AES-128-GCM. The only
//! private post-auth owner is libaegis AEGIS-128L, and only when the operator
//! selects it. There is no first-party AEGIS or MORUS implementation.

use serde::{Deserialize, Serialize};

// Internal compatibility aliases keep the moved source readable while making the crate boundary
// explicit: crypto owns the machine room and consumes only common, error, CPU, and telemetry
// contracts. No root product module is reachable from this crate.
pub(crate) use crate as crypto;
pub(crate) use qf_error as error;
pub(crate) use qf_telemetry as telemetry;

// Removed: rand::rngs::OsRng + RngCore. Secure randomness comes from
// qf-common's fill_secure_or_abort, which wraps getrandom directly and
// avoids coupling to any rand_core version.

// aarch64 intrinsics are imported locally where used via core::arch::aarch64

// Note: keep tests focused on functional behavior; avoid hygiene-only symbol touches.

#[cfg(test)]
mod tests;
mod tls_cover;

pub use tls_cover::{
    TlsCoverCipherKind, TlsCoverCipherState, TlsCoverInstallOutcome, TlsCoverKeyMaterial,
};

/// Manages cryptographic keys and provides secure random data.
/// This manager ensures that all cryptographic operations are backed by
/// secure, session-specific materials.
///
/// Retained by `StealthManager`, `CoreConnection`, and client subsystems
/// as a dependency-injection capability token; the struct itself is
/// zero-sized and carries no state. Key material comes from the canonical
/// secure-randomness contracts in `qf-common`.
pub struct CryptoManager;

impl CryptoManager {
    /// Create a new zero-sized crypto capability token.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// QUIC AEAD/HP and supporting primitives (moved from native.rs)
// -----------------------------------------------------------------------------

/// SHA-256, HMAC-SHA-256, and HKDF (RFC 5869) key derivation.
pub mod hkdf;

/// RFC 9001 compliant QUIC key derivation functions
pub mod quic_kdf;

/// AEAD/header-protection trait abstractions for QUIC packet protection.
/// Length of an AEAD authentication tag across every retained construction here.
pub(crate) const AEAD_TAG_LEN: usize = 16;

/// Total sealed length for `plaintext_len` bytes plus an authentication tag.
///
/// Returns `BufferTooShort` on overflow rather than wrapping. Every seal path used to compute
/// `len + 16` directly, so a caller-supplied length near `usize::MAX` wrapped in release builds
/// and panicked in debug ones. A wrapped total can also pass the capacity comparison that guards
/// `split_at_mut`, which turns a malformed length into an in-process abort instead of a typed
/// error.
#[inline]
pub(crate) fn sealed_len(plaintext_len: usize) -> Result<usize, crate::error::ConnectionError> {
    plaintext_len.checked_add(AEAD_TAG_LEN).ok_or(crate::error::ConnectionError::BufferTooShort)
}

/// Validate that `buf` can hold `plaintext_len` bytes plus a tag, returning the sealed length.
#[inline]
pub(crate) fn checked_seal_capacity(
    buf_len: usize,
    plaintext_len: usize,
) -> Result<usize, crate::error::ConnectionError> {
    let required = sealed_len(plaintext_len)?;
    if buf_len < required {
        return Err(crate::error::ConnectionError::BufferTooShort);
    }
    Ok(required)
}

pub mod aead;
mod libaegis_aead;
mod ring_aead;
pub use ring_aead::{aes128_gcm_tag_aad_only, RingAesGcm128, RingAesHp, RingChaCha20Poly1305};

const MAX_QUIC_PACKET_NUMBER: u64 = (1 << 62) - 1;

use crate::crypto::aead::{AeadOpen, AeadSeal};

fn validate_packet_number(counter: u64) -> Result<(), crate::error::ConnectionError> {
    if counter > MAX_QUIC_PACKET_NUMBER {
        return Err(crate::error::ConnectionError::CryptoError(
            "packet number exceeds the QUIC 62-bit limit".into(),
        ));
    }
    Ok(())
}

fn make_nonce16(iv: &[u8; 12], counter: u64) -> Result<[u8; 16], crate::error::ConnectionError> {
    validate_packet_number(counter)?;
    // QUIC-style nonce derivation for 96-bit IV: XOR 64-bit packet number
    // into the last 8 bytes of the 12-byte IV. Produce a 16-byte nonce by
    // copying the 12-byte IV into the first 12 bytes and leaving the last
    // 4 bytes as 0. This avoids 32-bit truncation. The primitive is stateless,
    // while this boundary still rejects packet numbers beyond QUIC's 62-bit
    // limit before deriving a nonce. The connection owner remains responsible
    // for traffic-secret uniqueness and monotonic key-update counters.
    let mut nonce16 = [0u8; 16];
    nonce16[..12].copy_from_slice(iv);
    let pn = counter.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        // XOR into bytes 4..12 (the last 8 bytes of the 12-byte IV)
        nonce16[4 + i] ^= pn[i];
    }
    Ok(nonce16)
}

pub type BoxedDataAeadPair = (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>);

enum DataAead {
    L(libaegis_aead::LibAegis128L),
    X2(libaegis_aead::LibAegis128X2),
    X4(libaegis_aead::LibAegis128X4),
}

impl DataAead {
    #[inline(always)]
    fn from_variant(
        variant: libaegis_aead::LibAegis128Variant,
        key: &[u8; 16],
        iv: &[u8; 12],
    ) -> Self {
        match variant {
            libaegis_aead::LibAegis128Variant::L => {
                Self::L(libaegis_aead::LibAegis128L::from_arrays(key, iv))
            }
            libaegis_aead::LibAegis128Variant::X2 => {
                Self::X2(libaegis_aead::LibAegis128X2::from_arrays(key, iv))
            }
            libaegis_aead::LibAegis128Variant::X4 => {
                Self::X4(libaegis_aead::LibAegis128X4::from_arrays(key, iv))
            }
        }
    }
}

macro_rules! dispatch_data_aead {
    ($self:expr, $method:ident($($arg:expr),* $(,)?)) => {
        match $self {
            DataAead::L(aead) => aead.$method($($arg),*),
            DataAead::X2(aead) => aead.$method($($arg),*),
            DataAead::X4(aead) => aead.$method($($arg),*),
        }
    };
}

impl AeadSeal for DataAead {
    #[inline(always)]
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        dispatch_data_aead!(self, seal_with_u64_counter(counter, ad, buf, len, extra_in))
    }

    #[inline(always)]
    fn supports_batch_seal(&self) -> bool {
        dispatch_data_aead!(self, supports_batch_seal())
    }

    #[inline(always)]
    fn seal_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        dispatch_data_aead!(self, seal_batch(items))
    }
}

impl AeadOpen for DataAead {
    #[inline(always)]
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        dispatch_data_aead!(self, open_with_u64_counter(counter, ad, buf))
    }

    #[inline(always)]
    fn supports_batch_open(&self) -> bool {
        dispatch_data_aead!(self, supports_batch_open())
    }

    #[inline(always)]
    fn open_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        dispatch_data_aead!(self, open_batch(items))
    }
}

enum PacketAeadSealInner {
    Data(DataAead),
    Dynamic(Box<dyn AeadSeal + Send + Sync>),
}

/// Packet seal dispatch used by the transport hot path.
pub struct PacketAeadSeal(PacketAeadSealInner);

impl PacketAeadSeal {
    fn data(aead: DataAead) -> Self {
        Self(PacketAeadSealInner::Data(aead))
    }

    /// Wrap a TLS/provider-owned packet seal implementation.
    pub fn dynamic(aead: Box<dyn AeadSeal + Send + Sync>) -> Self {
        Self(PacketAeadSealInner::Dynamic(aead))
    }
}

impl AeadSeal for PacketAeadSeal {
    #[inline(always)]
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        match &self.0 {
            PacketAeadSealInner::Data(aead) => {
                aead.seal_with_u64_counter(counter, ad, buf, len, extra_in)
            }
            PacketAeadSealInner::Dynamic(aead) => {
                aead.seal_with_u64_counter(counter, ad, buf, len, extra_in)
            }
        }
    }

    #[inline(always)]
    fn supports_batch_seal(&self) -> bool {
        match &self.0 {
            PacketAeadSealInner::Data(aead) => aead.supports_batch_seal(),
            PacketAeadSealInner::Dynamic(aead) => aead.supports_batch_seal(),
        }
    }

    #[inline(always)]
    fn seal_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match &self.0 {
            PacketAeadSealInner::Data(aead) => aead.seal_batch(items),
            PacketAeadSealInner::Dynamic(aead) => aead.seal_batch(items),
        }
    }
}

enum PacketAeadOpenInner {
    Data(DataAead),
    Dynamic(Box<dyn AeadOpen + Send + Sync>),
}

/// Packet open dispatch used by the transport hot path.
pub struct PacketAeadOpen(PacketAeadOpenInner);

impl PacketAeadOpen {
    fn data(aead: DataAead) -> Self {
        Self(PacketAeadOpenInner::Data(aead))
    }

    /// Wrap a TLS/provider-owned packet open implementation.
    pub fn dynamic(aead: Box<dyn AeadOpen + Send + Sync>) -> Self {
        Self(PacketAeadOpenInner::Dynamic(aead))
    }
}

impl AeadOpen for PacketAeadOpen {
    #[inline(always)]
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        match &self.0 {
            PacketAeadOpenInner::Data(aead) => aead.open_with_u64_counter(counter, ad, buf),
            PacketAeadOpenInner::Dynamic(aead) => aead.open_with_u64_counter(counter, ad, buf),
        }
    }

    #[inline(always)]
    fn supports_batch_open(&self) -> bool {
        match &self.0 {
            PacketAeadOpenInner::Data(aead) => aead.supports_batch_open(),
            PacketAeadOpenInner::Dynamic(aead) => aead.supports_batch_open(),
        }
    }

    #[inline(always)]
    fn open_batch(
        &self,
        items: &mut [crate::crypto::aead::AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        match &self.0 {
            PacketAeadOpenInner::Data(aead) => aead.open_batch(items),
            PacketAeadOpenInner::Dynamic(aead) => aead.open_batch(items),
        }
    }
}

/// Data-plane AEAD backend selector for benchmarks.
#[cfg(feature = "benches")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchDataAeadBackend {
    /// libaegis AEGIS-128L.
    Aegis128L,
}

#[cfg(feature = "benches")]
impl BenchDataAeadBackend {
    /// Returns the canonical lowercase name of this AEAD backend.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aegis128L => "aegis",
        }
    }
}

#[inline(always)]
fn record_libaegis_owner() {
    crate::telemetry::AEGIS_PLAN.store(1, std::sync::atomic::Ordering::Relaxed);
    qf_telemetry::DATA_AEAD_BACKEND_AEGIS_L_TOTAL.inc();
}

#[inline(always)]
fn build_data_aead(key: &[u8; 16], iv: &[u8; 12]) -> BoxedDataAeadPair {
    record_libaegis_owner();
    (
        Box::new(libaegis_aead::LibAegis128L::from_arrays(key, iv))
            as Box<dyn AeadSeal + Send + Sync>,
        Box::new(libaegis_aead::LibAegis128L::from_arrays(key, iv))
            as Box<dyn AeadOpen + Send + Sync>,
    )
}

#[inline(always)]
fn build_packet_data_aead(key: &[u8; 16], iv: &[u8; 12]) -> (PacketAeadSeal, PacketAeadOpen) {
    record_libaegis_owner();
    (
        PacketAeadSeal::data(DataAead::from_variant(libaegis_aead::LibAegis128Variant::L, key, iv)),
        PacketAeadOpen::data(DataAead::from_variant(libaegis_aead::LibAegis128Variant::L, key, iv)),
    )
}

/// Constructs a boxed seal/open pair for the libaegis benchmark backend.
#[cfg(feature = "benches")]
pub fn build_data_aead_for_benches(
    backend: BenchDataAeadBackend,
    key: &[u8],
    iv: &[u8],
) -> Result<BoxedDataAeadPair, crate::crypto::aead::KeyMaterialError> {
    crate::crypto::aead::require_exact_key_iv("data-plane AEAD", key, 16, iv, 12)?;
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(key);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(iv);
    let _ = backend;
    Ok(build_data_aead(&k16, &iv12))
}

/// Returns the libaegis seal/open pair. This is not the ship-default packet owner.
pub fn select_data_aead(
    key: &[u8],
    iv: &[u8],
) -> Result<BoxedDataAeadPair, crate::crypto::aead::KeyMaterialError> {
    crate::crypto::aead::require_exact_key_iv("data-plane AEAD", key, 16, iv, 12)?;
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(key);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(iv);
    Ok(build_data_aead(&k16, &iv12))
}

/// Returns the libaegis packet owner. This is not the ship-default packet owner.
pub fn select_packet_data_aead(key: &[u8; 32], iv: &[u8; 12]) -> (PacketAeadSeal, PacketAeadOpen) {
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(iv);
    build_packet_data_aead(&k16, &iv12)
}

/// Product-level private packet-AEAD family exposed to the authenticated negotiation layer.
///
/// Selecting AEGIS-128L is a fork-specific data-plane decision, not a TLS cipher-suite decision; it applies only under the explicit full-fork assumption (QuicFuscate-to-QuicFuscate peers).
/// The only family is libaegis AEGIS-128L. Wire id 2 (the removed MORUS id) is rejected by the decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateAeadFamily {
    /// libaegis AEGIS-128L with the exact 128-bit key profile.
    Aegis128L,
}

impl PrivateAeadFamily {
    /// Exact key length required by the private wire contract.
    pub const KEY_LEN: usize = 16;
    /// Exact packet IV length required by the private wire contract.
    pub const IV_LEN: usize = 12;
    /// Exact authentication tag length shared with the QUIC packet shape.
    pub const TAG_LEN: usize = 16;

    /// Stable protocol identifier. The removed MORUS id 2 is not assigned.
    pub const fn protocol_id(self) -> u8 {
        match self {
            Self::Aegis128L => 1,
        }
    }

    /// Stable low-cardinality diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aegis128L => "aegis",
        }
    }
}

/// Select a private packet AEAD with exact key and IV lengths.
///
/// This API is intentionally separate from the retained legacy selector, whose 32-byte input
/// represents a TLS-derived secret and historically feeds the first 16 bytes to the product
/// backend. Private negotiation must never silently truncate material, so it accepts only the
/// exact 128-bit family key and 96-bit packet IV.
pub fn select_private_packet_data_aead(
    family: PrivateAeadFamily,
    key: &[u8],
    iv: &[u8],
) -> Result<(PacketAeadSeal, PacketAeadOpen), crate::error::ConnectionError> {
    crate::crypto::aead::require_exact_key_iv(
        family.as_str(),
        key,
        PrivateAeadFamily::KEY_LEN,
        iv,
        PrivateAeadFamily::IV_LEN,
    )?;
    let mut key16 = [0u8; PrivateAeadFamily::KEY_LEN];
    key16.copy_from_slice(key);
    let mut iv12 = [0u8; PrivateAeadFamily::IV_LEN];
    iv12.copy_from_slice(iv);
    Ok(build_packet_data_aead(&key16, &iv12))
}

pub use libaegis_aead::LibAegis128Variant;

/// Build one libaegis AEGIS-128 packet owner.
///
/// `L`, `X2`, and `X4` do not open each other's ciphertext. The private
/// negotiation path stays on `L` until a same-host matrix pins a single variant.
pub fn select_libaegis128_packet(
    variant: LibAegis128Variant,
    key: &[u8; 16],
    iv: &[u8; 12],
) -> (PacketAeadSeal, PacketAeadOpen) {
    (
        PacketAeadSeal::data(DataAead::from_variant(variant, key, iv)),
        PacketAeadOpen::data(DataAead::from_variant(variant, key, iv)),
    )
}

/// Product-level private AEAD family preference.
///
/// `auto` selects no private family. Explicit `aegis` opts into libaegis
/// and is rejected when `packet_protection_mode` is `standard`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataAeadPreference {
    /// Select the backend from hardware and workload characteristics.
    #[default]
    Auto,
    /// Opt into libaegis AEGIS-128L. This is not selected by `auto`.
    #[serde(rename = "aegis")]
    Aegis128L,
}

impl DataAeadPreference {
    /// Convert the retained operator preference to the product-level private family contract.
    pub const fn private_family(self) -> Option<PrivateAeadFamily> {
        match self {
            Self::Auto => None,
            Self::Aegis128L => Some(PrivateAeadFamily::Aegis128L),
        }
    }
}

/// Packet-protection policy for the authenticated private data-plane upgrade.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PacketProtectionMode {
    /// Keep the complete connection on standards-compatible rustls QUIC keys.
    /// This is the shipped product default.
    #[default]
    Standard,
    /// Use standard protection unless an explicit authenticated private upgrade is configured.
    Auto,
    /// Require a completed authenticated private upgrade and fail closed otherwise.
    AdvancedRequired,
}

impl PacketProtectionMode {
    /// Stable low-cardinality diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Auto => "auto",
            Self::AdvancedRequired => "advanced-required",
        }
    }
}

/// Pin the post-auth payload cipher.
///
/// `use_aegis` is set for `off` and `performance`, and for `manual` when the
/// operator selected AEGIS-128L. Header protection, Initial, and handshake stay
/// rustls AES-128-GCM. Stealth-using modes pass `false` and keep AES-128-GCM
/// for the whole connection. The upgrade completes only when both peers agree.
pub const fn payload_protection_pin(
    use_aegis: bool,
) -> (PacketProtectionMode, Option<PrivateAeadFamily>) {
    if use_aegis {
        (PacketProtectionMode::Auto, Some(PrivateAeadFamily::Aegis128L))
    } else {
        (PacketProtectionMode::Standard, None)
    }
}

/// Cryptographic configuration projected from the engine boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CryptoConfig {
    /// Authenticated private packet-protection policy.
    pub packet_protection_mode: PacketProtectionMode,
    /// AEAD cipher preference.
    pub aead_preference: DataAeadPreference,
    /// Force a supported product-family AEAD name.
    pub force_aead: String,
    /// Deployment seed for the private protocol wire layout, hex encoded.
    /// Provisioned with the deployment's credential material and never
    /// negotiated on the wire. Empty keeps the canonical layout.
    pub private_shape_seed: String,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            packet_protection_mode: PacketProtectionMode::Standard,
            aead_preference: DataAeadPreference::Auto,
            force_aead: String::new(),
            private_shape_seed: String::new(),
        }
    }
}

impl CryptoConfig {
    /// Resolve the configured product family without exposing internal backend widths.
    pub fn private_family(&self) -> Option<PrivateAeadFamily> {
        let force = self.force_aead.trim().to_ascii_lowercase();
        match force.as_str() {
            "aegis" => Some(PrivateAeadFamily::Aegis128L),
            _ => self.aead_preference.private_family(),
        }
    }

    /// Decode the provisioned private protocol shape seed. Returns `None`
    /// when no seed is configured; malformed values fail validation, so a
    /// `Some` is always exactly 32 bytes.
    pub fn private_shape_seed_bytes(&self) -> Option<[u8; 32]> {
        let value = self.private_shape_seed.trim();
        if value.is_empty() {
            return None;
        }
        decode_hex_32(value)
    }

    /// Validate the operator-facing product-family override.
    pub fn validate(&self) -> Result<(), String> {
        let seed = self.private_shape_seed.trim();
        if !seed.is_empty() && decode_hex_32(seed).is_none() {
            return Err(
                "crypto.private_shape_seed must be 64 hex characters (32 bytes)".to_string()
            );
        }
        let force = self.force_aead.trim();
        if !force.is_empty() {
            let value = force.to_ascii_lowercase();
            let supported = matches!(value.as_str(), "auto" | "aegis");
            if !supported {
                return Err(format!("crypto.force_aead has unsupported value: {force}"));
            }
        }
        let private_requested = self.aead_preference != DataAeadPreference::Auto
            || !matches!(force.to_ascii_lowercase().as_str(), "" | "auto");
        match self.packet_protection_mode {
            PacketProtectionMode::Standard if private_requested => {
                return Err(
                    "crypto.packet_protection_mode=standard conflicts with a private AEAD selection"
                        .to_string(),
                );
            }
            PacketProtectionMode::AdvancedRequired if !private_requested => {
                return Err(
                    "crypto.packet_protection_mode=advanced-required requires an explicit private AEAD selection"
                        .to_string(),
                );
            }
            _ => {}
        }
        Ok(())
    }
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let (pairs, _) = value.as_bytes().as_chunks::<2>();
    for (index, pair) in pairs.iter().enumerate() {
        let high = match pair[0] {
            b'0'..=b'9' => pair[0] - b'0',
            b'a'..=b'f' => pair[0] - b'a' + 10,
            b'A'..=b'F' => pair[0] - b'A' + 10,
            _ => return None,
        };
        let low = match pair[1] {
            b'0'..=b'9' => pair[1] - b'0',
            b'a'..=b'f' => pair[1] - b'a' + 10,
            b'A'..=b'F' => pair[1] - b'A' + 10,
            _ => return None,
        };
        out[index] = (high << 4) | low;
    }
    Some(out)
}

/// Re-export of QUIC key derivation (HKDF-based Initial/Handshake/1-RTT key schedule).
pub use self::quic_kdf as kdf;
