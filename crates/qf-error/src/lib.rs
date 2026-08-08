//! Shared transport and runtime error contract for QuicFuscate workspace crates.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionError {
    CryptoError(String),
    ProtocolViolation,
    InvalidState,
    Timeout,
    InvalidFrame,
    Done,
    TlsError(String),
    TlsAlert(u64),
    BufferTooShort,
    PeerCertificateUnsupported,
    InvalidPacket,
    InvalidStreamState(u64),
    FinalSize,
    InternalError,
    Fec(String),
    Transport(String),
    StreamReset,
    StreamStopped,
    IdLimit,
    FlowControl,
    ApplicationError(u64),
    StreamLimit,
    ApplicationProtoError,
    VersionMismatch,
    FrameEncoding,
    InvalidToken,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
    ConnectionRefused,
    InvalidStreamId,
    /// QUIC DATAGRAM send queue is at capacity; the caller should apply
    /// backpressure and retry rather than drop the packet.
    DgramQueueFull,
    /// The local endpoint closed the transport connection.
    LocalConnectionClosed {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },
    /// The local endpoint closed the application connection.
    LocalApplicationClosed {
        error_code: u64,
        reason: Vec<u8>,
    },
    /// The peer closed the transport connection.
    PeerConnectionClosed {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },
    /// The peer closed the application connection.
    PeerApplicationClosed {
        error_code: u64,
        reason: Vec<u8>,
    },
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPacket => write!(f, "Invalid packet"),
            Self::InvalidFrame => write!(f, "Invalid frame"),
            Self::InvalidStreamId => write!(f, "Invalid stream ID"),
            Self::InvalidStreamState(_) => write!(f, "Invalid stream state"),
            Self::FlowControl => write!(f, "Flow control violation"),
            Self::StreamLimit => write!(f, "Stream limit exceeded"),
            Self::FinalSize => write!(f, "Final size error"),
            Self::FrameEncoding => write!(f, "Frame encoding error"),
            Self::ProtocolViolation => write!(f, "Protocol violation"),
            Self::InvalidToken => write!(f, "Invalid token"),
            Self::ApplicationError(code) => write!(f, "Application error: {code}"),
            Self::CryptoBufferExceeded => write!(f, "Crypto buffer exceeded"),
            Self::KeyUpdateError => write!(f, "Key update error"),
            Self::AeadLimitReached => write!(f, "AEAD limit reached"),
            Self::NoViablePath => write!(f, "No viable path"),
            Self::InternalError => write!(f, "Internal error"),
            Self::ConnectionRefused => write!(f, "Connection refused"),
            Self::Timeout => write!(f, "Timeout"),
            Self::Transport(message) => write!(f, "Transport error: {message}"),
            Self::TlsAlert(code) => write!(f, "TLS alert: {code}"),
            Self::PeerCertificateUnsupported => write!(f, "Peer certificate unsupported"),
            Self::Done => write!(f, "Connection done"),
            Self::BufferTooShort => write!(f, "Buffer too short"),
            Self::InvalidState => write!(f, "Invalid state"),
            Self::Fec(message) => write!(f, "FEC error: {message}"),
            Self::StreamReset => write!(f, "Stream reset"),
            Self::StreamStopped => write!(f, "Stream stopped"),
            Self::IdLimit => write!(f, "ID limit exceeded"),
            Self::LocalConnectionClosed { error_code, frame_type, reason } => write!(
                f,
                "Local connection closed: code={error_code} frame_type={frame_type} reason={}",
                String::from_utf8_lossy(reason)
            ),
            Self::LocalApplicationClosed { error_code, reason } => write!(
                f,
                "Local application closed: code={error_code} reason={}",
                String::from_utf8_lossy(reason)
            ),
            Self::PeerConnectionClosed { error_code, frame_type, reason } => write!(
                f,
                "Peer connection closed: code={error_code} frame_type={frame_type} reason={}",
                String::from_utf8_lossy(reason)
            ),
            Self::PeerApplicationClosed { error_code, reason } => write!(
                f,
                "Peer application closed: code={error_code} reason={}",
                String::from_utf8_lossy(reason)
            ),
            Self::CryptoError(message) => write!(f, "Crypto error: {message}"),
            Self::TlsError(message) => write!(f, "TLS error: {message}"),
            Self::ApplicationProtoError => write!(f, "Application protocol error"),
            Self::VersionMismatch => write!(f, "Version mismatch"),
            Self::DgramQueueFull => write!(f, "DATAGRAM send queue full"),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<String> for ConnectionError {
    fn from(message: String) -> Self {
        Self::Transport(message)
    }
}

impl From<&str> for ConnectionError {
    fn from(message: &str) -> Self {
        Self::Transport(message.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionError;

    #[test]
    fn string_conversions_preserve_transport_context() {
        assert_eq!(
            ConnectionError::from("socket closed"),
            ConnectionError::Transport("socket closed".to_string())
        );
        assert_eq!(
            ConnectionError::from(String::from("timeout")),
            ConnectionError::Transport("timeout".to_string())
        );
    }

    #[test]
    fn structured_close_display_includes_protocol_context() {
        let error = ConnectionError::PeerConnectionClosed {
            error_code: 42,
            frame_type: 7,
            reason: b"shutdown".to_vec(),
        };
        assert_eq!(
            error.to_string(),
            "Peer connection closed: code=42 frame_type=7 reason=shutdown"
        );
    }
}
