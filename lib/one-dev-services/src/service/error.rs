//! Enumerates errors for services.

use one_core::crypto::{CryptoProviderError, SignerError};
use one_core::provider::credential_formatter::error::FormatterError;
use one_core::provider::key_storage::error::KeyStorageProviderError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureServiceError {
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Could not sign")]
    CouldNotSign,
    #[error("Could not verify")]
    CouldNotVerify,
    #[error("Crypto provider error: `{0}`")]
    CryptoProviderError(#[from] CryptoProviderError),
    #[error("Signer error: `{0}`")]
    SignerError(#[from] SignerError),
}

#[derive(Debug, Error)]
pub enum CredentialServiceError {
    #[error("Missing algorithm `{0}`")]
    MissingFormat(String),
    #[error(transparent)]
    KeyStorageProviderError(#[from] KeyStorageProviderError),
    #[error(transparent)]
    FormatterError(#[from] FormatterError),
}
