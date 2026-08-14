//! Typed, secret-free runtime truth for QUIC packet protection.

/// Standard TLS 1.3 cipher suite that owns Handshake and standard 1-RTT keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StandardCipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302).
    Aes256GcmSha384,
}

impl StandardCipherSuite {
    /// IANA TLS cipher-suite identifier.
    pub const fn tls_id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
        }
    }

    /// Stable low-cardinality label for logs, metrics, and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes128GcmSha256 => "tls-aes-128-gcm-sha256",
            Self::Aes256GcmSha384 => "tls-aes-256-gcm-sha384",
        }
    }
}

/// Concrete owner of one installed packet- or header-protection key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketProtectionOwner {
    /// The encryption level is intentionally disabled.
    Disabled,
    /// No key has been installed yet.
    Uninstalled,
    /// RFC-defined QUIC Initial key derivation owns the key.
    QuicInitialStandard,
    /// rustls QUIC owns the key from the negotiated TLS 1.3 suite.
    RustlsStandard,
    /// The transport compatibility key schedule owns a standard AES-GCM key.
    TransportStandard,
    /// An authenticated private post-handshake mode owns the key.
    PrivateAdvanced,
    /// An atomic owner transition is in progress.
    Transitioning,
}

impl PacketProtectionOwner {
    /// Stable low-cardinality label for logs, metrics, and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Uninstalled => "uninstalled",
            Self::QuicInitialStandard => "quic-initial-standard",
            Self::RustlsStandard => "rustls-standard",
            Self::TransportStandard => "transport-standard",
            Self::PrivateAdvanced => "private-advanced",
            Self::Transitioning => "transitioning",
        }
    }
}

/// Effective packet-protection state for one QUIC encryption level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketProtectionLevelSnapshot {
    /// Owner of the packet payload AEAD key.
    pub packet_aead_owner: PacketProtectionOwner,
    /// Owner of the header-protection key.
    pub header_protection_owner: PacketProtectionOwner,
    /// Negotiated standard suite when the level is standards-owned.
    pub standard_cipher_suite: Option<StandardCipherSuite>,
}

impl PacketProtectionLevelSnapshot {
    pub(crate) const fn uninstalled() -> Self {
        Self {
            packet_aead_owner: PacketProtectionOwner::Uninstalled,
            header_protection_owner: PacketProtectionOwner::Uninstalled,
            standard_cipher_suite: None,
        }
    }

    pub(crate) const fn disabled() -> Self {
        Self {
            packet_aead_owner: PacketProtectionOwner::Disabled,
            header_protection_owner: PacketProtectionOwner::Disabled,
            standard_cipher_suite: None,
        }
    }
}

/// Connection-owned snapshot of effective QUIC packet protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketProtectionSnapshot {
    /// Initial packet protection.
    pub initial: PacketProtectionLevelSnapshot,
    /// Handshake packet protection.
    pub handshake: PacketProtectionLevelSnapshot,
    /// 0-RTT packet protection, disabled until separately implemented.
    pub zero_rtt: PacketProtectionLevelSnapshot,
    /// 1-RTT packet protection.
    pub one_rtt: PacketProtectionLevelSnapshot,
    /// Cipher suite observed from the real rustls connection.
    pub negotiated_tls_cipher_suite: Option<StandardCipherSuite>,
}

impl Default for PacketProtectionSnapshot {
    fn default() -> Self {
        Self {
            initial: PacketProtectionLevelSnapshot::uninstalled(),
            handshake: PacketProtectionLevelSnapshot::uninstalled(),
            zero_rtt: PacketProtectionLevelSnapshot::disabled(),
            one_rtt: PacketProtectionLevelSnapshot::uninstalled(),
            negotiated_tls_cipher_suite: None,
        }
    }
}
