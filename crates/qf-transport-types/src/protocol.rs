//! Root-independent packet protocol value contracts.

use super::ConnectionId;
use std::ops::{Index, IndexMut};

/// QUIC packet epoch used by the transport and TLS handshake paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Epoch {
    /// Initial encryption level used during connection establishment.
    Initial = 0,
    /// Handshake encryption level used during TLS negotiation.
    Handshake = 1,
    /// Application data encryption level after the handshake.
    Application = 2,
}

const EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Application];

impl Epoch {
    /// Returns the inclusive epoch range as a static slice.
    pub fn epochs(range: std::ops::RangeInclusive<Epoch>) -> &'static [Epoch] {
        &EPOCHS[*range.start() as usize..=*range.end() as usize]
    }

    /// Returns the number of supported packet epochs.
    pub const fn count() -> usize {
        EPOCHS.len()
    }
}

impl From<Epoch> for usize {
    fn from(epoch: Epoch) -> Self {
        epoch as usize
    }
}

impl<T> Index<Epoch> for [T] {
    type Output = T;

    fn index(&self, epoch: Epoch) -> &Self::Output {
        self.index(usize::from(epoch))
    }
}

impl<T> IndexMut<Epoch> for [T] {
    fn index_mut(&mut self, epoch: Epoch) -> &mut Self::Output {
        self.index_mut(usize::from(epoch))
    }
}

/// Packet-level transport errors shared by QUIC and HTTP/3 adapters.
#[derive(Debug, Clone, PartialEq)]
pub enum TransportError {
    /// Operation would block.
    Done,
    /// FEC error.
    Fec,
    /// Generic transport backend error.
    Transport,
    /// Buffer is too short.
    BufferTooShort,
    /// Unknown version.
    UnknownVersion,
    /// Invalid frame.
    InvalidFrame,
    /// Invalid packet.
    InvalidPacket,
    /// Invalid state.
    InvalidState,
    /// Invalid stream state.
    InvalidStreamState,
    /// Invalid transport parameter.
    InvalidTransportParam,
    /// Crypto error.
    CryptoFail,
    /// TLS handshake error.
    TlsFail,
    /// Flow-control error.
    FlowControl,
    /// Stream limit error.
    StreamLimit,
    /// Stream stopped.
    StreamStopped,
    /// Stream was reset by the peer.
    StreamReset(u64, u64),
    /// Final-size error.
    FinalSize,
    /// Connection-ID limit error.
    IdLimit,
    /// Out of identifiers.
    OutOfIdentifiers,
    /// Key-update error.
    KeyUpdate,
    /// AEAD limit reached.
    AeadLimitReached,
    /// No viable path.
    NoViablePath,
    /// Connection timeout.
    TimedOut,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TransportError {}

/// QUIC packet type used by packet parsing and frame legality checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// Initial packet carrying the first handshake messages.
    Initial,
    /// Retry packet used for address validation.
    Retry,
    /// Handshake packet carrying TLS handshake messages.
    Handshake,
    /// 0-RTT packet carrying early application data.
    ZeroRTT,
    /// Version Negotiation packet without encrypted frames.
    VersionNegotiation,
    /// Short-header 1-RTT application packet.
    Short,
}

impl PacketType {
    /// Maps a packet epoch to its corresponding encrypted packet type.
    pub const fn from_epoch(epoch: Epoch) -> Self {
        match epoch {
            Epoch::Initial => Self::Initial,
            Epoch::Handshake => Self::Handshake,
            Epoch::Application => Self::Short,
        }
    }

    /// Returns the packet epoch when this packet carries encrypted frames.
    pub fn to_epoch(self) -> Result<Epoch, TransportError> {
        match self {
            Self::Initial => Ok(Epoch::Initial),
            Self::ZeroRTT => Ok(Epoch::Application),
            Self::Handshake => Ok(Epoch::Handshake),
            Self::Short => Ok(Epoch::Application),
            Self::Retry | Self::VersionNegotiation => Err(TransportError::InvalidPacket),
        }
    }
}

/// Root-independent decoded QUIC packet header metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    /// Packet type (Initial, Handshake, Short, etc.).
    pub ty: PacketType,
    /// QUIC version field, or zero for short-header packets.
    pub version: u32,
    /// Destination connection ID.
    pub dcid: ConnectionId,
    /// Source connection ID, empty for short-header packets.
    pub scid: ConnectionId,
    /// Decoded packet number.
    pub pkt_num: u64,
    /// On-wire packet-number encoding length in bytes.
    pub pkt_num_len: usize,
    /// Token from Initial or Retry packets.
    pub token: Option<Vec<u8>>,
    /// Supported versions from Version Negotiation packets.
    pub versions: Option<Vec<u32>>,
    /// Key-phase bit for short-header packets.
    pub key_phase: bool,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Header")
            .field("ty", &self.ty)
            .field("version", &self.version)
            .field("dcid", &self.dcid)
            .field("scid", &self.scid)
            .field("pkt_num", &self.pkt_num)
            .field("pkt_num_len", &self.pkt_num_len)
            .field("token", &self.token)
            .field("versions", &self.versions)
            .field("key_phase", &self.key_phase)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_ranges_and_indexing_are_stable() {
        assert_eq!(Epoch::count(), 3);
        assert_eq!(
            Epoch::epochs(Epoch::Handshake..=Epoch::Application),
            &[Epoch::Handshake, Epoch::Application]
        );
        let mut values = [10_u8, 20, 30];
        assert_eq!(values[Epoch::Initial], 10);
        values[Epoch::Application] = 31;
        assert_eq!(values, [10, 20, 31]);
    }

    #[test]
    fn packet_epoch_mapping_rejects_unencrypted_packets() {
        assert_eq!(PacketType::from_epoch(Epoch::Initial), PacketType::Initial);
        assert_eq!(PacketType::ZeroRTT.to_epoch(), Ok(Epoch::Application));
        assert_eq!(PacketType::Retry.to_epoch(), Err(TransportError::InvalidPacket));
        assert_eq!(PacketType::VersionNegotiation.to_epoch(), Err(TransportError::InvalidPacket));
    }

    #[test]
    fn header_keeps_connection_ids_and_packet_metadata() {
        let header = Header {
            ty: PacketType::Initial,
            version: 1,
            dcid: ConnectionId::from_ref(&[1, 2, 3]),
            scid: ConnectionId::from_ref(&[4, 5]),
            pkt_num: 7,
            pkt_num_len: 2,
            token: Some(vec![9]),
            versions: None,
            key_phase: false,
        };
        assert_eq!(header.dcid.as_ref(), &[1, 2, 3]);
        assert_eq!(header.scid.as_ref(), &[4, 5]);
        assert_eq!(header.pkt_num_len, 2);
    }
}
