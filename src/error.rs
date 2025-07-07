use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("quiche error: {0}")]
    Quiche(#[from] quiche::Error),
    #[error("fec error: {0}")]
    Fec(String),
}

impl From<&'static str> for ConnectionError {
    fn from(s: &'static str) -> Self {
        ConnectionError::Fec(s.to_string())
    }
}

impl From<String> for ConnectionError {
    fn from(s: String) -> Self {
        ConnectionError::Fec(s)
    }
}

