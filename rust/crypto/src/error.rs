use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("authentication tag mismatch")]
    InvalidTag,
    #[error("OpenSSL initialization failed")]
    OpenSsl,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
