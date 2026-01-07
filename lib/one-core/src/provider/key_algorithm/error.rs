//! Enumerates errors related to the key algorithm provider.

use one_crypto::SignerError;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};

#[derive(Debug, Error)]
pub enum KeyAlgorithmProviderError {
    #[error("Cannot find key algorithm `{0}`")]
    MissingAlgorithmImplementation(String),
    #[error("Cannot find signer `{0}`")]
    MissingSignerImplementation(String),

    #[error("Key algorithm error: `{0}`")]
    KeyAlgorithm(KeyAlgorithmError),
}

#[derive(Debug, Error)]
pub enum KeyAlgorithmError {
    #[error("Key algorithm error: `{0}`")]
    Failed(String),
    #[error("Signer error: `{0}`")]
    SignerError(#[from] SignerError),
    #[error("Not supported for type: `{0}`")]
    NotSupported(String),
}

impl ErrorCodeMixin for KeyAlgorithmError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0063
    }
}
