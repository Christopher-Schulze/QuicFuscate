//! Versioned, authenticated private packet-protection control contract.
//!
//! This module owns the protocol boundary only. It does not activate a private packet owner by
//! itself. A connection must still prove TLS completion, QKey authentication, peer confirmation,
//! and packet-key installation before a transport caller can use the derived material.

use qf_common::secret::SecretBytes;
use qf_crypto::{hkdf, PacketProtectionMode, PrivateAeadFamily};
use std::fmt;

/// Private control capsule type reserved for the authenticated QuicFuscate packet-AEAD protocol.
///
/// This value is in the MASQUE capsule namespace. Its numeric equality with the H3
/// WebTransport stream-signal value is harmless because those values are parsed in different
/// namespaces and never share a decoder.
pub const PRIVATE_PACKET_PROTECTION_CAPSULE_TYPE: u64 = 0x41;
/// Current private packet-protection protocol version.
pub const PRIVATE_PACKET_PROTECTION_VERSION: u8 = 1;
/// Maximum encoded private control payload.
pub const MAX_PRIVATE_PACKET_PROTECTION_PAYLOAD: usize = 512;
/// Maximum negotiated ALPN bytes retained in the transcript.
pub const MAX_PRIVATE_ALPN_LEN: usize = 255;
/// QUIC permits connection IDs up to twenty bytes.
pub const MAX_PRIVATE_CONNECTION_ID_LEN: usize = 20;
/// Nonces are fixed-length and never reused by a connection generation.
pub const PRIVATE_NONCE_LEN: usize = 16;
/// Transcript and confirmation hashes use SHA-256.
pub const PRIVATE_HASH_LEN: usize = 32;
/// The packet AEAD profile retains QUIC's sixteen-byte tag shape.
pub const PRIVATE_TAG_LEN: usize = 16;

const MAGIC: [u8; 4] = *b"QFPA";
const KNOWN_FLAGS: u16 = 0;
const EXPORTER_SALT: &[u8] = b"quicfuscate private packet protection v1";
const EXPORTER_LABEL: &[u8] = b"qf private packet aead v1";
/// Exporter label used by the live Core owner.
pub const PRIVATE_EXPORTER_LABEL: &[u8] = EXPORTER_LABEL;
/// Context domain used to bind the exporter to one authenticated connection generation.
pub const PRIVATE_EXPORTER_CONTEXT_DOMAIN: &[u8] = b"qf private packet exporter context v1";

/// Message kind carried on the authenticated control capsule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrivateNegotiationKind {
    /// Advertise the frozen product-family capability after authentication.
    Proposal = 1,
    /// Select one mutually supported product family.
    Selection = 2,
    /// Confirm the selection and the deterministic packet boundary.
    Confirmation = 3,
}

impl PrivateNegotiationKind {
    fn decode(value: u8) -> Result<Self, PrivateProtocolError> {
        match value {
            1 => Ok(Self::Proposal),
            2 => Ok(Self::Selection),
            3 => Ok(Self::Confirmation),
            _ => Err(PrivateProtocolError::InvalidField("message kind")),
        }
    }
}

/// Role encoded into the transcript so direction labels cannot be swapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrivateNegotiationRole {
    /// Client endpoint.
    Client = 1,
    /// Server endpoint.
    Server = 2,
}

impl PrivateNegotiationRole {
    fn decode(value: u8) -> Result<Self, PrivateProtocolError> {
        match value {
            1 => Ok(Self::Client),
            2 => Ok(Self::Server),
            _ => Err(PrivateProtocolError::InvalidField("role")),
        }
    }

    fn opposite(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Explicit state machine for the authenticated private upgrade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateNegotiationState {
    /// TLS or QKey authentication is not complete.
    StandardHandshake,
    /// Standard 1-RTT is active and the authenticated control path is available.
    StandardAuthenticated,
    /// This endpoint has sent a proposal.
    ProposalSent,
    /// This endpoint has received a proposal and has not selected yet.
    ProposalReceived,
    /// Both sides have selected the same family, but the boundary is not committed.
    SelectionConfirmed,
    /// Both write boundaries are committed and the switch is ready.
    SwitchScheduled,
    /// Private payload protection is active at or above the committed boundary.
    AdvancedActive,
    /// A private epoch update is in progress.
    AdvancedUpdating,
    /// Standards-only fallback selected before private activation.
    StandardFallback,
    /// The connection cannot safely continue.
    Terminal,
}

/// Direction label used by the private key schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateDirection {
    /// Client-to-server packet direction.
    ClientToServer,
    /// Server-to-client packet direction.
    ServerToClient,
}

impl PrivateDirection {
    fn label(self) -> &'static [u8] {
        match self {
            Self::ClientToServer => b"client-write",
            Self::ServerToClient => b"server-write",
        }
    }
}

/// Secret-owned private payload material for one direction and epoch.
pub struct PrivateKeyMaterial {
    /// Exact 16-byte family key.
    pub key: SecretBytes,
    /// Exact 12-byte packet IV.
    pub iv: SecretBytes,
}

/// Connection-bound exporter schedule for private packet epochs.
///
/// The schedule keeps the exporter root inside the existing zeroizing owner and exposes only
/// direction-labelled derivation. Transport owners can therefore advance a private epoch without
/// receiving raw TLS traffic secrets or reconstructing the transcript themselves.
pub(crate) struct PrivateEpochSchedule {
    root: SecretBytes,
    family: PrivateAeadFamily,
    context_hash: [u8; PRIVATE_HASH_LEN],
}

impl fmt::Debug for PrivateEpochSchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEpochSchedule")
            .field("family", &self.family.as_str())
            .field("context_hash_bound", &true)
            .finish()
    }
}

impl PrivateEpochSchedule {
    pub(crate) const fn family(&self) -> PrivateAeadFamily {
        self.family
    }

    pub(crate) fn derive(
        &self,
        direction: PrivateDirection,
        epoch: u32,
    ) -> Result<PrivateKeyMaterial, PrivateProtocolError> {
        if epoch == 0 {
            return Err(PrivateProtocolError::InvalidField("epoch"));
        }
        let mut info = Vec::with_capacity(128);
        info.extend_from_slice(EXPORTER_LABEL);
        info.push(self.family.protocol_id());
        info.extend_from_slice(direction.label());
        info.extend_from_slice(&epoch.to_be_bytes());
        info.extend_from_slice(&self.context_hash);
        let prk = hkdf::hkdf_extract(EXPORTER_SALT, self.root.as_slice());
        let material =
            hkdf::hkdf_expand(&prk, &info, PrivateAeadFamily::KEY_LEN + PrivateAeadFamily::IV_LEN);
        let key =
            SecretBytes::new(material[..PrivateAeadFamily::KEY_LEN].to_vec(), "private_packet_key");
        let iv =
            SecretBytes::new(material[PrivateAeadFamily::KEY_LEN..].to_vec(), "private_packet_iv");
        Ok(PrivateKeyMaterial { key, iv })
    }
}

impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKeyMaterial")
            .field("key_len", &self.key.as_slice().len())
            .field("iv_len", &self.iv.as_slice().len())
            .finish()
    }
}

/// Strictly bounded private control message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateNegotiationMessage {
    /// Protocol version.
    pub version: u8,
    /// Message kind.
    pub kind: PrivateNegotiationKind,
    /// Monotonic connection-generation identifier.
    pub generation: u32,
    /// Bit mask of supported product families: bit 0 AEGIS, bit 1 MORUS.
    pub supported_families: u8,
    /// Selected family, absent only in a proposal.
    pub selected_family: Option<PrivateAeadFamily>,
    /// Sender role.
    pub role: PrivateNegotiationRole,
    /// Feature flags. Unknown bits are rejected.
    pub flags: u16,
    /// Exact key size carried in the protocol profile.
    pub key_len: u8,
    /// Exact IV size carried in the protocol profile.
    pub iv_len: u8,
    /// Exact tag size carried in the protocol profile.
    pub tag_len: u8,
    /// Key epoch.
    pub epoch: u32,
    /// Sender write boundary in decoded packet-number space.
    pub write_boundary: u64,
    /// QUIC version bound to the transcript.
    pub quic_version: u32,
    /// Sender nonce.
    pub local_nonce: [u8; PRIVATE_NONCE_LEN],
    /// Peer nonce, zeroed only in a proposal.
    pub peer_nonce: [u8; PRIVATE_NONCE_LEN],
    /// Authenticated QKey transcript hash.
    pub qkey_transcript_hash: [u8; PRIVATE_HASH_LEN],
    /// Context hash binding all non-secret connection parameters.
    pub context_hash: [u8; PRIVATE_HASH_LEN],
    /// Negotiated ALPN bytes.
    pub alpn: Vec<u8>,
    /// Original destination connection ID.
    pub original_dcid: Vec<u8>,
    /// Current destination connection ID.
    pub current_dcid: Vec<u8>,
    /// HMAC-SHA-256 over the canonical message without this field.
    pub authenticator: [u8; PRIVATE_HASH_LEN],
}

impl PrivateNegotiationMessage {
    /// Validate all bounded fields and message-specific invariants.
    pub fn validate(&self) -> Result<(), PrivateProtocolError> {
        if self.version != PRIVATE_PACKET_PROTECTION_VERSION {
            return Err(PrivateProtocolError::UnsupportedVersion(self.version));
        }
        if self.generation == 0 {
            return Err(PrivateProtocolError::InvalidField("generation"));
        }
        if self.supported_families == 0 || self.supported_families & !0x03 != 0 {
            return Err(PrivateProtocolError::InvalidField("supported families"));
        }
        if self.flags & !KNOWN_FLAGS != 0 {
            return Err(PrivateProtocolError::UnknownCriticalFlags);
        }
        if self.key_len as usize != PrivateAeadFamily::KEY_LEN
            || self.iv_len as usize != PrivateAeadFamily::IV_LEN
            || self.tag_len as usize != PrivateAeadFamily::TAG_LEN
        {
            return Err(PrivateProtocolError::InvalidField("AEAD parameter profile"));
        }
        if self.write_boundary > ((1u64 << 62) - 1) {
            return Err(PrivateProtocolError::InvalidField("write boundary"));
        }
        if self.alpn.is_empty() || self.alpn.len() > MAX_PRIVATE_ALPN_LEN {
            return Err(PrivateProtocolError::InvalidField("ALPN"));
        }
        if self.original_dcid.is_empty() || self.current_dcid.is_empty() {
            return Err(PrivateProtocolError::InvalidField("canonical connection ID"));
        }
        if self.original_dcid.len() > MAX_PRIVATE_CONNECTION_ID_LEN
            || self.current_dcid.len() > MAX_PRIVATE_CONNECTION_ID_LEN
        {
            return Err(PrivateProtocolError::InvalidField("connection ID"));
        }
        if self.local_nonce.iter().all(|byte| *byte == 0) {
            return Err(PrivateProtocolError::InvalidField("local nonce"));
        }
        match self.kind {
            PrivateNegotiationKind::Proposal => {
                if self.selected_family.is_some()
                    || self.write_boundary != 0
                    || self.epoch != 0
                    || self.peer_nonce.iter().any(|byte| *byte != 0)
                {
                    return Err(PrivateProtocolError::InvalidField("proposal fields"));
                }
            }
            PrivateNegotiationKind::Selection => {
                let family = self
                    .selected_family
                    .ok_or(PrivateProtocolError::InvalidField("selected family"))?;
                if !family_is_supported(self.supported_families, family)
                    || self.peer_nonce.iter().all(|byte| *byte == 0)
                    || self.write_boundary != 0
                    || self.epoch != 0
                {
                    return Err(PrivateProtocolError::InvalidField("selection fields"));
                }
            }
            PrivateNegotiationKind::Confirmation => {
                let family = self
                    .selected_family
                    .ok_or(PrivateProtocolError::InvalidField("selected family"))?;
                if !family_is_supported(self.supported_families, family)
                    || self.peer_nonce.iter().all(|byte| *byte == 0)
                    || self.write_boundary == 0
                    || self.epoch != 0
                {
                    return Err(PrivateProtocolError::InvalidField("confirmation fields"));
                }
            }
        }
        Ok(())
    }

    /// Encode and authenticate the message with the post-authentication exporter root.
    pub fn encode_authenticated(
        &self,
        exporter_root: &[u8],
    ) -> Result<Vec<u8>, PrivateProtocolError> {
        self.validate()?;
        if exporter_root.len() != PRIVATE_HASH_LEN {
            return Err(PrivateProtocolError::InvalidSecretLength);
        }
        let mut authenticated = self.clone();
        authenticated.authenticator = [0u8; PRIVATE_HASH_LEN];
        let canonical = authenticated.encode_raw()?;
        authenticated.authenticator = hkdf::hmac_sha256(exporter_root, &canonical);
        authenticated.encode_raw()
    }

    /// Decode a bounded message without accepting trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateProtocolError> {
        if bytes.len() > MAX_PRIVATE_PACKET_PROTECTION_PAYLOAD {
            return Err(PrivateProtocolError::PayloadTooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != MAGIC {
            return Err(PrivateProtocolError::InvalidField("magic"));
        }
        let version = reader.u8()?;
        let kind = PrivateNegotiationKind::decode(reader.u8()?)?;
        let generation = reader.u32()?;
        let supported_families = reader.u8()?;
        let selected_family = decode_family(reader.u8()?)?;
        let role = PrivateNegotiationRole::decode(reader.u8()?)?;
        let flags = reader.u16()?;
        let key_len = reader.u8()?;
        let iv_len = reader.u8()?;
        let tag_len = reader.u8()?;
        let epoch = reader.u32()?;
        let write_boundary = reader.u64()?;
        let quic_version = reader.u32()?;
        let alpn_len = reader.u8()? as usize;
        let original_dcid_len = reader.u8()? as usize;
        let current_dcid_len = reader.u8()? as usize;
        if reader.u8()? != 0 {
            return Err(PrivateProtocolError::InvalidField("reserved byte"));
        }
        if alpn_len > MAX_PRIVATE_ALPN_LEN
            || original_dcid_len > MAX_PRIVATE_CONNECTION_ID_LEN
            || current_dcid_len > MAX_PRIVATE_CONNECTION_ID_LEN
        {
            return Err(PrivateProtocolError::InvalidField("length bound"));
        }
        let local_nonce = reader.array::<PRIVATE_NONCE_LEN>()?;
        let peer_nonce = reader.array::<PRIVATE_NONCE_LEN>()?;
        let qkey_transcript_hash = reader.array::<PRIVATE_HASH_LEN>()?;
        let context_hash = reader.array::<PRIVATE_HASH_LEN>()?;
        let alpn = reader.bytes(alpn_len)?.to_vec();
        let original_dcid = reader.bytes(original_dcid_len)?.to_vec();
        let current_dcid = reader.bytes(current_dcid_len)?.to_vec();
        let authenticator = reader.array::<PRIVATE_HASH_LEN>()?;
        let message = Self {
            version,
            kind,
            generation,
            supported_families,
            selected_family,
            role,
            flags,
            key_len,
            iv_len,
            tag_len,
            epoch,
            write_boundary,
            quic_version,
            alpn,
            local_nonce,
            peer_nonce,
            qkey_transcript_hash,
            context_hash,
            original_dcid,
            current_dcid,
            authenticator,
        };
        if !reader.is_empty() {
            return Err(PrivateProtocolError::TrailingBytes);
        }
        message.validate()?;
        Ok(message)
    }

    /// Verify the transcript authenticator without exposing the exporter root.
    pub fn verify_authenticated(&self, exporter_root: &[u8]) -> Result<(), PrivateProtocolError> {
        if exporter_root.len() != PRIVATE_HASH_LEN {
            return Err(PrivateProtocolError::InvalidSecretLength);
        }
        self.validate()?;
        let mut unsigned = self.clone();
        unsigned.authenticator = [0u8; PRIVATE_HASH_LEN];
        let expected = hkdf::hmac_sha256(exporter_root, &unsigned.encode_raw()?);
        if !constant_time_equal(&expected, &self.authenticator) {
            return Err(PrivateProtocolError::AuthenticationFailed);
        }
        Ok(())
    }

    fn encode_raw(&self) -> Result<Vec<u8>, PrivateProtocolError> {
        let alpn_len = u8::try_from(self.alpn.len())
            .map_err(|_| PrivateProtocolError::InvalidField("ALPN length"))?;
        let original_len = u8::try_from(self.original_dcid.len())
            .map_err(|_| PrivateProtocolError::InvalidField("original DCID length"))?;
        let current_len = u8::try_from(self.current_dcid.len())
            .map_err(|_| PrivateProtocolError::InvalidField("current DCID length"))?;
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(self.version);
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.push(self.supported_families);
        bytes.push(self.selected_family.map_or(0, PrivateAeadFamily::protocol_id));
        bytes.push(self.role as u8);
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.push(self.key_len);
        bytes.push(self.iv_len);
        bytes.push(self.tag_len);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.write_boundary.to_be_bytes());
        bytes.extend_from_slice(&self.quic_version.to_be_bytes());
        bytes.push(alpn_len);
        bytes.push(original_len);
        bytes.push(current_len);
        bytes.push(0);
        bytes.extend_from_slice(&self.local_nonce);
        bytes.extend_from_slice(&self.peer_nonce);
        bytes.extend_from_slice(&self.qkey_transcript_hash);
        bytes.extend_from_slice(&self.context_hash);
        bytes.extend_from_slice(&self.alpn);
        bytes.extend_from_slice(&self.original_dcid);
        bytes.extend_from_slice(&self.current_dcid);
        bytes.extend_from_slice(&self.authenticator);
        if bytes.len() > MAX_PRIVATE_PACKET_PROTECTION_PAYLOAD {
            return Err(PrivateProtocolError::PayloadTooLarge);
        }
        Ok(bytes)
    }
}

/// Authenticated state holder for one connection generation.
pub struct PrivateNegotiationMachine {
    mode: PacketProtectionMode,
    role: PrivateNegotiationRole,
    preferred_family: Option<PrivateAeadFamily>,
    supported_families: u8,
    generation: u32,
    quic_version: u32,
    alpn: Vec<u8>,
    original_dcid: Vec<u8>,
    current_dcid: Vec<u8>,
    qkey_transcript_hash: [u8; PRIVATE_HASH_LEN],
    local_nonce: [u8; PRIVATE_NONCE_LEN],
    peer_nonce: Option<[u8; PRIVATE_NONCE_LEN]>,
    peer_supported_families: Option<u8>,
    exporter_root: Option<SecretBytes>,
    selected_family: Option<PrivateAeadFamily>,
    write_boundary: Option<u64>,
    peer_write_boundary: Option<u64>,
    state: PrivateNegotiationState,
}

impl fmt::Debug for PrivateNegotiationMachine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateNegotiationMachine")
            .field("mode", &self.mode.as_str())
            .field("role", &self.role)
            .field("generation", &self.generation)
            .field("state", &self.state)
            .field("selected_family", &self.selected_family.map(PrivateAeadFamily::as_str))
            .field("has_exporter_root", &self.exporter_root.is_some())
            .finish()
    }
}

impl PrivateNegotiationMachine {
    /// Create a machine in the standard handshake state.
    ///
    /// `original_dcid` and `current_dcid` must already be canonical role-ordered connection
    /// context values. This boundary deliberately does not infer endpoint-specific QUIC IDs;
    /// the transport owner must normalize them before constructing the machine.
    #[allow(
        clippy::too_many_arguments,
        reason = "The constructor requires every transcript-bound connection field explicitly; defaults would make the private protocol context ambiguous."
    )]
    pub fn new(
        mode: PacketProtectionMode,
        role: PrivateNegotiationRole,
        preferred_family: Option<PrivateAeadFamily>,
        generation: u32,
        quic_version: u32,
        alpn: Vec<u8>,
        original_dcid: Vec<u8>,
        current_dcid: Vec<u8>,
        qkey_transcript_hash: [u8; PRIVATE_HASH_LEN],
        local_nonce: [u8; PRIVATE_NONCE_LEN],
    ) -> Result<Self, PrivateProtocolError> {
        if generation == 0 || local_nonce.iter().all(|byte| *byte == 0) {
            return Err(PrivateProtocolError::InvalidField("generation or nonce"));
        }
        if alpn.is_empty() || alpn.len() > MAX_PRIVATE_ALPN_LEN {
            return Err(PrivateProtocolError::InvalidField("ALPN"));
        }
        if mode != PacketProtectionMode::Standard
            && (original_dcid.is_empty() || current_dcid.is_empty())
        {
            return Err(PrivateProtocolError::InvalidField("canonical connection ID"));
        }
        if original_dcid.len() > MAX_PRIVATE_CONNECTION_ID_LEN
            || current_dcid.len() > MAX_PRIVATE_CONNECTION_ID_LEN
        {
            return Err(PrivateProtocolError::InvalidField("connection ID"));
        }
        if qkey_transcript_hash.iter().all(|byte| *byte == 0) {
            return Err(PrivateProtocolError::InvalidField("QKey transcript hash"));
        }
        let supported_families = preferred_family.map_or(0, family_mask);
        let state = if mode == PacketProtectionMode::Standard {
            PrivateNegotiationState::StandardFallback
        } else {
            PrivateNegotiationState::StandardHandshake
        };
        Ok(Self {
            mode,
            role,
            preferred_family,
            supported_families,
            generation,
            quic_version,
            alpn,
            original_dcid,
            current_dcid,
            qkey_transcript_hash,
            local_nonce,
            peer_nonce: None,
            peer_supported_families: None,
            exporter_root: None,
            selected_family: None,
            write_boundary: None,
            peer_write_boundary: None,
            state,
        })
    }

    /// Install the exact 32-byte exporter root after TLS and QKey authentication.
    pub fn install_exporter_root(
        &mut self,
        exporter_root: &[u8],
    ) -> Result<(), PrivateProtocolError> {
        if exporter_root.len() != PRIVATE_HASH_LEN {
            return Err(PrivateProtocolError::InvalidSecretLength);
        }
        self.exporter_root =
            Some(SecretBytes::new(exporter_root.to_vec(), "private_packet_exporter_root"));
        Ok(())
    }

    /// Mark TLS plus QKey authentication complete. No control message is emitted before this.
    pub fn mark_authenticated(&mut self) -> Result<(), PrivateProtocolError> {
        if self.mode == PacketProtectionMode::Standard {
            self.state = PrivateNegotiationState::StandardFallback;
            return Ok(());
        }
        if self.exporter_root.is_none() || self.state != PrivateNegotiationState::StandardHandshake
        {
            return Err(PrivateProtocolError::InvalidState);
        }
        self.state = PrivateNegotiationState::StandardAuthenticated;
        Ok(())
    }

    /// Build the first authenticated proposal.
    pub fn build_proposal(&mut self) -> Result<PrivateNegotiationMessage, PrivateProtocolError> {
        if self.role != PrivateNegotiationRole::Client
            || self.state != PrivateNegotiationState::StandardAuthenticated
        {
            return Err(PrivateProtocolError::InvalidState);
        }
        if self.supported_families == 0 {
            return self.fallback_or_fail();
        }
        let message = self.message(PrivateNegotiationKind::Proposal, None, 0, 0, None)?;
        self.state = PrivateNegotiationState::ProposalSent;
        Ok(message)
    }

    /// Accept and authenticate a peer proposal.
    pub fn receive_proposal(
        &mut self,
        message: &PrivateNegotiationMessage,
    ) -> Result<(), PrivateProtocolError> {
        if let Err(error) = self.verify_peer_message(message, PrivateNegotiationKind::Proposal) {
            return self.fail_closed(error);
        }
        if self.role != PrivateNegotiationRole::Server
            || self.state != PrivateNegotiationState::StandardAuthenticated
        {
            return self.fail_closed(PrivateProtocolError::InvalidState);
        }
        self.peer_nonce = Some(message.local_nonce);
        self.peer_supported_families = Some(message.supported_families);
        self.state = PrivateNegotiationState::ProposalReceived;
        Ok(())
    }

    /// Select the configured frozen family from the peer proposal.
    pub fn build_selection(&mut self) -> Result<PrivateNegotiationMessage, PrivateProtocolError> {
        if self.role != PrivateNegotiationRole::Server
            || self.state != PrivateNegotiationState::ProposalReceived
        {
            return Err(PrivateProtocolError::InvalidState);
        }
        let Some(family) = self.preferred_family.filter(|family| {
            family_is_supported(self.supported_families, *family)
                && self
                    .peer_supported_families
                    .is_some_and(|mask| family_is_supported(mask, *family))
        }) else {
            return self.fallback_or_fail();
        };
        self.selected_family = Some(family);
        let message = self.message(PrivateNegotiationKind::Selection, Some(family), 0, 0, None)?;
        self.state = PrivateNegotiationState::SelectionConfirmed;
        Ok(message)
    }

    /// Accept an authenticated selection matching the local proposal.
    pub fn receive_selection(
        &mut self,
        message: &PrivateNegotiationMessage,
    ) -> Result<(), PrivateProtocolError> {
        if let Err(error) = self.verify_peer_message(message, PrivateNegotiationKind::Selection) {
            return self.fail_closed(error);
        }
        if self.role != PrivateNegotiationRole::Client
            || self.state != PrivateNegotiationState::ProposalSent
        {
            return self.fail_closed(PrivateProtocolError::InvalidState);
        }
        let family = match message.selected_family {
            Some(family) => family,
            None => return self.fail_closed(PrivateProtocolError::InvalidField("selected family")),
        };
        if self.preferred_family != Some(family) {
            return self.fail_closed(PrivateProtocolError::DowngradeDetected);
        }
        if message.peer_nonce != self.local_nonce {
            return self.fail_closed(PrivateProtocolError::ContextMismatch);
        }
        self.peer_nonce = Some(message.local_nonce);
        self.selected_family = Some(family);
        self.state = PrivateNegotiationState::SelectionConfirmed;
        Ok(())
    }

    /// Commit this endpoint's deterministic standard-to-private write boundary.
    pub fn build_confirmation(
        &mut self,
        write_boundary: u64,
    ) -> Result<PrivateNegotiationMessage, PrivateProtocolError> {
        if self.state != PrivateNegotiationState::SelectionConfirmed || write_boundary == 0 {
            return Err(PrivateProtocolError::InvalidState);
        }
        if write_boundary > ((1u64 << 62) - 1) {
            return Err(PrivateProtocolError::InvalidField("write boundary"));
        }
        self.write_boundary = Some(write_boundary);
        let family = self.selected_family.ok_or(PrivateProtocolError::InvalidState)?;
        let message = self.message(
            PrivateNegotiationKind::Confirmation,
            Some(family),
            write_boundary,
            0,
            self.peer_nonce,
        )?;
        self.state = if self.peer_write_boundary.is_some() {
            PrivateNegotiationState::SwitchScheduled
        } else {
            PrivateNegotiationState::SelectionConfirmed
        };
        Ok(message)
    }

    /// Accept the peer's deterministic write boundary.
    pub fn receive_confirmation(
        &mut self,
        message: &PrivateNegotiationMessage,
    ) -> Result<(), PrivateProtocolError> {
        if let Err(error) = self.verify_peer_message(message, PrivateNegotiationKind::Confirmation)
        {
            return self.fail_closed(error);
        }
        if self.state != PrivateNegotiationState::SelectionConfirmed {
            return self.fail_closed(PrivateProtocolError::InvalidState);
        }
        if self.selected_family != message.selected_family
            || self.peer_nonce != Some(message.local_nonce)
            || message.peer_nonce != self.local_nonce
        {
            return self.fail_closed(PrivateProtocolError::DowngradeDetected);
        }
        self.peer_write_boundary = Some(message.write_boundary);
        self.state = if self.write_boundary.is_some() {
            PrivateNegotiationState::SwitchScheduled
        } else {
            PrivateNegotiationState::SelectionConfirmed
        };
        Ok(())
    }

    /// Activate the private payload owner only after both boundaries are committed.
    pub fn activate(&mut self) -> Result<(), PrivateProtocolError> {
        if self.state != PrivateNegotiationState::SwitchScheduled
            || self.selected_family.is_none()
            || self.write_boundary.is_none()
            || self.peer_write_boundary.is_none()
        {
            return Err(PrivateProtocolError::InvalidState);
        }
        self.state = PrivateNegotiationState::AdvancedActive;
        Ok(())
    }

    /// Terminate an upgrade whose transport-owner installation did not complete.
    pub(crate) fn terminate(&mut self) {
        if self.mode != PacketProtectionMode::Standard {
            self.state = PrivateNegotiationState::Terminal;
        } else {
            self.state = PrivateNegotiationState::StandardFallback;
        }
    }

    /// Derive one exact directional key/IV pair for the current private epoch.
    pub fn derive_material(
        &self,
        direction: PrivateDirection,
        epoch: u32,
    ) -> Result<PrivateKeyMaterial, PrivateProtocolError> {
        if !matches!(
            self.state,
            PrivateNegotiationState::SwitchScheduled | PrivateNegotiationState::AdvancedActive
        ) || epoch == 0
        {
            return Err(PrivateProtocolError::InvalidState);
        }
        self.epoch_schedule()?.derive(direction, epoch)
    }

    /// Return the authenticated, connection-bound epoch schedule after both confirmations.
    pub(crate) fn epoch_schedule(&self) -> Result<PrivateEpochSchedule, PrivateProtocolError> {
        if !matches!(
            self.state,
            PrivateNegotiationState::SwitchScheduled | PrivateNegotiationState::AdvancedActive
        ) {
            return Err(PrivateProtocolError::InvalidState);
        }
        let family = self.selected_family.ok_or(PrivateProtocolError::InvalidState)?;
        let root = self.exporter_root.as_ref().ok_or(PrivateProtocolError::InvalidState)?;
        Ok(PrivateEpochSchedule {
            root: root.clone(),
            family,
            context_hash: self.full_context_hash()?,
        })
    }

    /// Return the current protocol state without exposing secret material.
    pub const fn state(&self) -> PrivateNegotiationState {
        self.state
    }

    /// Return the selected public product family, if one is committed.
    pub const fn selected_family(&self) -> Option<PrivateAeadFamily> {
        self.selected_family
    }

    /// Return this endpoint's committed standard-to-private write boundary.
    pub const fn write_boundary(&self) -> Option<u64> {
        self.write_boundary
    }

    /// Return the peer's committed standard-to-private write boundary.
    pub const fn peer_write_boundary(&self) -> Option<u64> {
        self.peer_write_boundary
    }

    fn message(
        &self,
        kind: PrivateNegotiationKind,
        selected_family: Option<PrivateAeadFamily>,
        write_boundary: u64,
        epoch: u32,
        peer_nonce_override: Option<[u8; PRIVATE_NONCE_LEN]>,
    ) -> Result<PrivateNegotiationMessage, PrivateProtocolError> {
        let peer_nonce = peer_nonce_override.or(self.peer_nonce).unwrap_or([0; PRIVATE_NONCE_LEN]);
        let context_hash = self.context_hash(peer_nonce);
        let message = PrivateNegotiationMessage {
            version: PRIVATE_PACKET_PROTECTION_VERSION,
            kind,
            generation: self.generation,
            supported_families: self.supported_families,
            selected_family,
            role: self.role,
            flags: 0,
            key_len: PrivateAeadFamily::KEY_LEN as u8,
            iv_len: PrivateAeadFamily::IV_LEN as u8,
            tag_len: PrivateAeadFamily::TAG_LEN as u8,
            epoch,
            write_boundary,
            quic_version: self.quic_version,
            local_nonce: self.local_nonce,
            peer_nonce,
            qkey_transcript_hash: self.qkey_transcript_hash,
            context_hash,
            alpn: self.alpn.clone(),
            original_dcid: self.original_dcid.clone(),
            current_dcid: self.current_dcid.clone(),
            authenticator: [0u8; PRIVATE_HASH_LEN],
        };
        let root = self.exporter_root.as_ref().ok_or(PrivateProtocolError::InvalidState)?;
        let encoded = message.encode_authenticated(root.as_slice())?;
        PrivateNegotiationMessage::decode(&encoded)
    }

    /// Authenticate an already validated state-machine message for the H3 control owner.
    pub(crate) fn encode_message(
        &self,
        message: &PrivateNegotiationMessage,
    ) -> Result<Vec<u8>, PrivateProtocolError> {
        let root = self.exporter_root.as_ref().ok_or(PrivateProtocolError::InvalidState)?;
        message.encode_authenticated(root.as_slice())
    }

    fn verify_peer_message(
        &self,
        message: &PrivateNegotiationMessage,
        expected_kind: PrivateNegotiationKind,
    ) -> Result<(), PrivateProtocolError> {
        if message.kind != expected_kind
            || message.role != self.role.opposite()
            || message.generation != self.generation
            || message.quic_version != self.quic_version
            || message.alpn != self.alpn
            || message.original_dcid != self.original_dcid
            || message.current_dcid != self.current_dcid
            || message.qkey_transcript_hash != self.qkey_transcript_hash
        {
            return Err(PrivateProtocolError::ContextMismatch);
        }
        let root = self.exporter_root.as_ref().ok_or(PrivateProtocolError::InvalidState)?;
        message.verify_authenticated(root.as_slice())?;
        let expected_context_hash = if message.kind == PrivateNegotiationKind::Proposal {
            self.role_ordered_context_hash(message.local_nonce, [0; PRIVATE_NONCE_LEN])
        } else {
            self.context_hash(message.local_nonce)
        };
        if message.context_hash != expected_context_hash {
            return Err(PrivateProtocolError::ContextMismatch);
        }
        Ok(())
    }

    fn context_hash(&self, peer_nonce: [u8; PRIVATE_NONCE_LEN]) -> [u8; PRIVATE_HASH_LEN] {
        let (client_nonce, server_nonce) = match self.role {
            PrivateNegotiationRole::Client => (self.local_nonce, peer_nonce),
            PrivateNegotiationRole::Server => (peer_nonce, self.local_nonce),
        };
        self.role_ordered_context_hash(client_nonce, server_nonce)
    }

    fn role_ordered_context_hash(
        &self,
        client_nonce: [u8; PRIVATE_NONCE_LEN],
        server_nonce: [u8; PRIVATE_NONCE_LEN],
    ) -> [u8; PRIVATE_HASH_LEN] {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"qf-private-context-v1");
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.quic_version.to_be_bytes());
        bytes.extend_from_slice(&client_nonce);
        bytes.extend_from_slice(&server_nonce);
        bytes.extend_from_slice(&self.qkey_transcript_hash);
        push_bounded(&mut bytes, &self.alpn);
        push_bounded(&mut bytes, &self.original_dcid);
        push_bounded(&mut bytes, &self.current_dcid);
        hkdf::sha256(&bytes)
    }

    fn full_context_hash(&self) -> Result<[u8; PRIVATE_HASH_LEN], PrivateProtocolError> {
        self.peer_nonce
            .map(|nonce| self.context_hash(nonce))
            .ok_or(PrivateProtocolError::InvalidState)
    }

    fn fail_closed<T>(&mut self, error: PrivateProtocolError) -> Result<T, PrivateProtocolError> {
        if self.mode != PacketProtectionMode::Standard {
            self.state = PrivateNegotiationState::Terminal;
        }
        Err(error)
    }

    fn fallback_or_fail(&mut self) -> Result<PrivateNegotiationMessage, PrivateProtocolError> {
        match self.mode {
            PacketProtectionMode::Auto => {
                self.state = PrivateNegotiationState::StandardFallback;
                Err(PrivateProtocolError::StandardFallback)
            }
            PacketProtectionMode::AdvancedRequired => {
                self.state = PrivateNegotiationState::Terminal;
                Err(PrivateProtocolError::NoCommonFamily)
            }
            PacketProtectionMode::Standard => {
                self.state = PrivateNegotiationState::StandardFallback;
                Err(PrivateProtocolError::StandardFallback)
            }
        }
    }
}

fn family_mask(family: PrivateAeadFamily) -> u8 {
    1u8 << (family.protocol_id() - 1)
}

fn family_is_supported(mask: u8, family: PrivateAeadFamily) -> bool {
    mask & family_mask(family) != 0
}

fn decode_family(value: u8) -> Result<Option<PrivateAeadFamily>, PrivateProtocolError> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(PrivateAeadFamily::Aegis128L)),
        2 => Ok(Some(PrivateAeadFamily::Morus1280_128)),
        _ => Err(PrivateProtocolError::InvalidField("family")),
    }
}

fn push_bounded(target: &mut Vec<u8>, bytes: &[u8]) {
    target.push(bytes.len().min(u8::MAX as usize) as u8);
    target.extend_from_slice(bytes);
}

fn constant_time_equal(left: &[u8; PRIVATE_HASH_LEN], right: &[u8; PRIVATE_HASH_LEN]) -> bool {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PrivateProtocolError> {
        let end = self.offset.checked_add(length).ok_or(PrivateProtocolError::Truncated)?;
        let value = self.bytes.get(self.offset..end).ok_or(PrivateProtocolError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PrivateProtocolError> {
        Ok(*self.take(1)?.first().ok_or(PrivateProtocolError::Truncated)?)
    }

    fn u16(&mut self) -> Result<u16, PrivateProtocolError> {
        let mut value = [0u8; 2];
        value.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(value))
    }

    fn u32(&mut self) -> Result<u32, PrivateProtocolError> {
        let mut value = [0u8; 4];
        value.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(value))
    }

    fn u64(&mut self) -> Result<u64, PrivateProtocolError> {
        let mut value = [0u8; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(value))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PrivateProtocolError> {
        let mut value = [0u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], PrivateProtocolError> {
        self.take(length)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Errors returned by the private protocol boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivateProtocolError {
    /// A bounded payload exceeded its contract.
    PayloadTooLarge,
    /// The payload ended before a required field.
    Truncated,
    /// Bytes remained after the complete message.
    TrailingBytes,
    /// A field or combination violated the protocol contract.
    InvalidField(&'static str),
    /// A peer used a protocol version not understood by this build.
    UnsupportedVersion(u8),
    /// Unknown critical flags were present.
    UnknownCriticalFlags,
    /// The exporter root was not exactly 32 bytes.
    InvalidSecretLength,
    /// The message authenticator did not verify.
    AuthenticationFailed,
    /// The authenticated context did not match this connection generation.
    ContextMismatch,
    /// A peer attempted a downgrade or conflicting selection.
    DowngradeDetected,
    /// No frozen family is mutually supported.
    NoCommonFamily,
    /// The caller attempted an illegal state transition.
    InvalidState,
    /// Auto mode selected standards-only fallback before private activation.
    StandardFallback,
}

impl fmt::Display for PrivateProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => {
                formatter.write_str("private packet protection payload too large")
            }
            Self::Truncated => formatter.write_str("private packet protection payload truncated"),
            Self::TrailingBytes => {
                formatter.write_str("private packet protection payload has trailing bytes")
            }
            Self::InvalidField(field) => {
                write!(formatter, "invalid private packet protection field: {field}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported private packet protection version: {version}")
            }
            Self::UnknownCriticalFlags => {
                formatter.write_str("unknown critical private packet protection flags")
            }
            Self::InvalidSecretLength => {
                formatter.write_str("private packet protection exporter root must be 32 bytes")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("private packet protection authenticator failed")
            }
            Self::ContextMismatch => {
                formatter.write_str("private packet protection context mismatch")
            }
            Self::DowngradeDetected => {
                formatter.write_str("private packet protection downgrade detected")
            }
            Self::NoCommonFamily => {
                formatter.write_str("no mutually supported private packet protection family")
            }
            Self::InvalidState => {
                formatter.write_str("invalid private packet protection state transition")
            }
            Self::StandardFallback => {
                formatter.write_str("private packet protection fell back to standard QUIC")
            }
        }
    }
}

impl std::error::Error for PrivateProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(role: PrivateNegotiationRole) -> PrivateNegotiationMachine {
        PrivateNegotiationMachine::new(
            PacketProtectionMode::Auto,
            role,
            Some(PrivateAeadFamily::Aegis128L),
            7,
            1,
            b"h3".to_vec(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            [0x44; PRIVATE_HASH_LEN],
            if role == PrivateNegotiationRole::Client {
                [0x11; PRIVATE_NONCE_LEN]
            } else {
                [0x22; PRIVATE_NONCE_LEN]
            },
        )
        .expect("machine")
    }

    fn authenticated_pair() -> (PrivateNegotiationMachine, PrivateNegotiationMachine) {
        let mut client = machine(PrivateNegotiationRole::Client);
        let mut server = machine(PrivateNegotiationRole::Server);
        client.install_exporter_root(&[0x77; PRIVATE_HASH_LEN]).expect("client root");
        server.install_exporter_root(&[0x77; PRIVATE_HASH_LEN]).expect("server root");
        client.mark_authenticated().expect("client auth");
        server.mark_authenticated().expect("server auth");
        (client, server)
    }

    #[test]
    fn proposal_roundtrip_is_bounded_and_authenticated() {
        let (mut client, mut server) = authenticated_pair();
        let proposal = client.build_proposal().expect("proposal");
        let encoded = proposal.encode_authenticated(&[0x77; PRIVATE_HASH_LEN]).expect("encode");
        let decoded = PrivateNegotiationMessage::decode(&encoded).expect("decode");
        decoded.verify_authenticated(&[0x77; PRIVATE_HASH_LEN]).expect("auth");
        server.receive_proposal(&decoded).expect("receive proposal");
        assert_eq!(server.state(), PrivateNegotiationState::ProposalReceived);
    }

    #[test]
    fn selection_confirmation_and_activation_are_deterministic() {
        let (mut client, mut server) = authenticated_pair();
        let proposal = client.build_proposal().expect("proposal");
        server.receive_proposal(&proposal).expect("proposal");
        let selection = server.build_selection().expect("selection");
        client.receive_selection(&selection).expect("selection");
        let client_confirmation = client.build_confirmation(100).expect("client boundary");
        server.receive_confirmation(&client_confirmation).expect("client confirmation");
        let server_confirmation = server.build_confirmation(200).expect("server boundary");
        client.receive_confirmation(&server_confirmation).expect("server confirmation");
        server.activate().expect("server activation");
        client.activate().expect("client activation");
        assert_eq!(client.state(), PrivateNegotiationState::AdvancedActive);
        assert_eq!(server.state(), PrivateNegotiationState::AdvancedActive);
        let client_material =
            client.derive_material(PrivateDirection::ClientToServer, 1).expect("client material");
        let server_material =
            server.derive_material(PrivateDirection::ClientToServer, 1).expect("server material");
        assert_eq!(client_material.key.as_slice(), server_material.key.as_slice());
        assert_eq!(client_material.iv.as_slice(), server_material.iv.as_slice());
    }

    #[test]
    fn tampering_truncation_context_and_downgrade_fail_closed() {
        let (mut client, mut server) = authenticated_pair();
        let proposal = client.build_proposal().expect("proposal");
        let mut encoded = proposal.encode_authenticated(&[0x77; PRIVATE_HASH_LEN]).expect("encode");
        encoded.pop();
        assert!(matches!(
            PrivateNegotiationMessage::decode(&encoded),
            Err(PrivateProtocolError::Truncated)
        ));

        let mut tampered = proposal.clone();
        tampered.context_hash[0] ^= 1;
        assert!(tampered.verify_authenticated(&[0x77; PRIVATE_HASH_LEN]).is_err());

        server.receive_proposal(&proposal).expect("proposal");
        let selection = server.build_selection().expect("selection");
        let mut downgrade = selection.clone();
        downgrade.selected_family = Some(PrivateAeadFamily::Morus1280_128);
        assert!(client.receive_selection(&downgrade).is_err());
    }

    #[test]
    fn standard_mode_never_enters_private_states() {
        let mut standard = PrivateNegotiationMachine::new(
            PacketProtectionMode::Standard,
            PrivateNegotiationRole::Client,
            Some(PrivateAeadFamily::Aegis128L),
            1,
            1,
            b"h3".to_vec(),
            Vec::new(),
            Vec::new(),
            [0x11; PRIVATE_HASH_LEN],
            [0x22; PRIVATE_NONCE_LEN],
        )
        .expect("standard machine");
        standard.install_exporter_root(&[0x33; PRIVATE_HASH_LEN]).expect("root");
        standard.mark_authenticated().expect("standard auth");
        assert_eq!(standard.state(), PrivateNegotiationState::StandardFallback);
        assert!(matches!(standard.build_proposal(), Err(PrivateProtocolError::InvalidState)));
    }

    #[test]
    fn incompatible_private_families_fallback_or_terminal_without_activation() {
        let mut client = PrivateNegotiationMachine::new(
            PacketProtectionMode::Auto,
            PrivateNegotiationRole::Client,
            Some(PrivateAeadFamily::Aegis128L),
            7,
            1,
            b"h3".to_vec(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            [0x44; PRIVATE_HASH_LEN],
            [0x11; PRIVATE_NONCE_LEN],
        )
        .expect("client machine");
        let mut server = PrivateNegotiationMachine::new(
            PacketProtectionMode::AdvancedRequired,
            PrivateNegotiationRole::Server,
            Some(PrivateAeadFamily::Morus1280_128),
            7,
            1,
            b"h3".to_vec(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            [0x44; PRIVATE_HASH_LEN],
            [0x22; PRIVATE_NONCE_LEN],
        )
        .expect("server machine");
        for machine in [&mut client, &mut server] {
            machine.install_exporter_root(&[0x77; PRIVATE_HASH_LEN]).expect("root");
            machine.mark_authenticated().expect("auth");
        }

        let proposal = client.build_proposal().expect("proposal");
        server.receive_proposal(&proposal).expect("proposal");
        assert!(matches!(server.build_selection(), Err(PrivateProtocolError::NoCommonFamily)));
        assert_eq!(server.state(), PrivateNegotiationState::Terminal);

        let mut auto_server = PrivateNegotiationMachine::new(
            PacketProtectionMode::Auto,
            PrivateNegotiationRole::Server,
            Some(PrivateAeadFamily::Morus1280_128),
            7,
            1,
            b"h3".to_vec(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            [0x44; PRIVATE_HASH_LEN],
            [0x22; PRIVATE_NONCE_LEN],
        )
        .expect("auto server machine");
        auto_server.install_exporter_root(&[0x77; PRIVATE_HASH_LEN]).expect("root");
        auto_server.mark_authenticated().expect("auth");
        auto_server.receive_proposal(&proposal).expect("proposal");
        assert!(matches!(
            auto_server.build_selection(),
            Err(PrivateProtocolError::StandardFallback)
        ));
        assert_eq!(auto_server.state(), PrivateNegotiationState::StandardFallback);
    }

    #[test]
    fn private_mode_requires_nonempty_canonical_connection_context() {
        let error = PrivateNegotiationMachine::new(
            PacketProtectionMode::Auto,
            PrivateNegotiationRole::Client,
            Some(PrivateAeadFamily::Aegis128L),
            1,
            1,
            b"h3".to_vec(),
            Vec::new(),
            vec![4, 5, 6],
            [0x44; PRIVATE_HASH_LEN],
            [0x11; PRIVATE_NONCE_LEN],
        )
        .expect_err("private mode must require canonical connection IDs");
        assert_eq!(error, PrivateProtocolError::InvalidField("canonical connection ID"));
    }
}
