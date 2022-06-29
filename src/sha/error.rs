use thiserror::Error;

/// Custom error type
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid HMAC Key
    #[error("invalid key")]
    InvalidKey,
}

/// Alias to a `Resuly<T, Error>` with the cutom [enum@Error].
pub type Result<T> = std::result::Result<T, Error>;
