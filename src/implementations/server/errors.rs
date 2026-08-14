use super::session::SessionError;

/// Errors returned when accepting a client session.
#[derive(Debug, Clone)]
pub enum AcceptError {
    MaxClientsReached,
    TooManyConnectionsPerIp,
    IpPoolExhausted,
    SessionError(String),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxClientsReached => write!(f, "Maximum clients reached"),
            Self::TooManyConnectionsPerIp => write!(f, "Too many connections from this IP"),
            Self::IpPoolExhausted => write!(f, "IP pool exhausted"),
            Self::SessionError(error) => write!(f, "Session error: {error}"),
        }
    }
}

impl std::error::Error for AcceptError {}

impl From<SessionError> for AcceptError {
    fn from(error: SessionError) -> Self {
        Self::SessionError(error.to_string())
    }
}
