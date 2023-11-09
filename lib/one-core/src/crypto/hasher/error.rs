use thiserror::Error;

use crate::crypto::error::CryptoProviderError;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum HasherError {
    #[error("Could not hash")]
    CouldNotHash,
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
}
