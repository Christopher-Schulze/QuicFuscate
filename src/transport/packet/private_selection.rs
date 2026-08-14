use super::*;

/// Deterministic selection result for the authenticated private 1-RTT payload owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivatePacketProtectionSelection {
    /// Use the currently committed standard QUIC payload opener/sealer.
    Standard,
    /// Use the negotiated private payload opener/sealer.
    Advanced,
}

/// Select the 1-RTT payload owner from a decoded packet number and a committed boundary.
///
/// Header protection must already have been removed before this function is called. A missing
/// boundary or a disabled direction is always standard, so configuration alone can never switch
/// a packet onto the private owner.
#[inline(always)]
pub(crate) fn select_private_packet_protection(
    packet_number: u64,
    boundary: Option<u64>,
    enabled: bool,
) -> PrivatePacketProtectionSelection {
    if enabled && boundary.is_some_and(|boundary| boundary != 0 && packet_number >= boundary) {
        PrivatePacketProtectionSelection::Advanced
    } else {
        PrivatePacketProtectionSelection::Standard
    }
}

#[inline(always)]
pub(crate) fn select_private_seal<'a>(
    standard: Option<&'a Arc<crate::crypto::PacketAeadSeal>>,
    private: Option<&'a Arc<crate::crypto::PacketAeadSeal>>,
    packet_number: u64,
    boundary: Option<u64>,
) -> Result<&'a dyn tls_aead::AeadSeal, ConnectionError> {
    match select_private_packet_protection(packet_number, boundary, private.is_some()) {
        PrivatePacketProtectionSelection::Standard => standard
            .map(|seal| seal.as_ref() as &dyn tls_aead::AeadSeal)
            .ok_or(ConnectionError::Done),
        PrivatePacketProtectionSelection::Advanced => private
            .map(|seal| seal.as_ref() as &dyn tls_aead::AeadSeal)
            .ok_or(ConnectionError::Done),
    }
}

#[inline(always)]
#[allow(
    clippy::too_many_arguments,
    reason = "the hot-path selector keeps every epoch boundary and phase explicit"
)]
pub(crate) fn select_private_open_for_phase<'a>(
    standard: Option<&'a Arc<crate::crypto::PacketAeadOpen>>,
    private: Option<&'a Arc<crate::crypto::PacketAeadOpen>>,
    next_private: Option<&'a Arc<crate::crypto::PacketAeadOpen>>,
    previous_private: &'a [PreviousPrivateReadEpoch],
    packet_number: u64,
    boundary: Option<u64>,
    packet_key_phase: bool,
    current_key_phase: bool,
    next_key_phase: bool,
    current_start_packet_number: Option<u64>,
    next_ready: bool,
) -> Result<&'a dyn tls_aead::AeadOpen, ConnectionError> {
    match select_private_packet_protection(packet_number, boundary, private.is_some()) {
        PrivatePacketProtectionSelection::Standard => standard
            .map(|open| open.as_ref() as &dyn tls_aead::AeadOpen)
            .ok_or(ConnectionError::Done),
        PrivatePacketProtectionSelection::Advanced => {
            if current_start_packet_number.is_some_and(|start| packet_number < start) {
                if let Some(open) = previous_private
                    .iter()
                    .rev()
                    .find(|epoch| {
                        epoch.key_phase == packet_key_phase
                            && packet_number >= epoch.start_packet_number
                    })
                    .map(|epoch| &epoch.open)
                {
                    return Ok(open.as_ref() as &dyn tls_aead::AeadOpen);
                }
                return Err(ConnectionError::CryptoError(
                    "private packet number rolled back before the current epoch".into(),
                ));
            }
            if packet_key_phase == current_key_phase {
                return private
                    .map(|open| open.as_ref() as &dyn tls_aead::AeadOpen)
                    .ok_or(ConnectionError::Done);
            }
            if packet_key_phase == next_key_phase && next_ready {
                return next_private
                    .map(|open| open.as_ref() as &dyn tls_aead::AeadOpen)
                    .ok_or_else(|| {
                        ConnectionError::CryptoError(
                            "private next read epoch has not been staged".into(),
                        )
                    });
            }
            if let Some(open) = previous_private
                .iter()
                .rev()
                .find(|epoch| {
                    epoch.key_phase == packet_key_phase
                        && packet_number >= epoch.start_packet_number
                })
                .map(|epoch| &epoch.open)
            {
                return Ok(open.as_ref() as &dyn tls_aead::AeadOpen);
            }
            Err(ConnectionError::CryptoError(
                "private key phase is outside the bounded epoch window".into(),
            ))
        }
    }
}
