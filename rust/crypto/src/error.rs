use thiserror::Error;
use quicfuscate_error::QuicFuscateError;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("authentication tag mismatch")]
    InvalidTag,
    #[error("OpenSSL initialization failed")]
    OpenSsl,
}

impl QuicFuscateError for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;
