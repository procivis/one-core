//! Enumerates errors related to the key algorithm provider.

use one_crypto::SignerError;
use standardized_types::jwk::JwkUse;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum KeyAlgorithmProviderError {
    #[error("Cannot find key algorithm `{0}`")]
    MissingAlgorithmImplementation(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for KeyAlgorithmProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingAlgorithmImplementation(_) => ErrorCode::BR_0042,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Error)]
pub enum KeyAlgorithmError {
    #[error("Missing key parameter: `{0}`")]
    MissingParameter(String),
    #[error("Invalid key type")]
    InvalidKeyType,
    #[error("Invalid key encoding: `{0}`")]
    InvalidEncoding(String),
    #[error("Invalid key use: `{0}`")]
    InvalidUse(JwkUse),
    #[error("Not supported for type: `{0}`")]
    NotSupported(String),

    #[error("Signer error: `{0}`")]
    SignerError(#[from] SignerError),
    #[error("Decoding error: `{0}`")]
    DecodeError(#[from] bs58::decode::Error),
    #[error("Encoding error: `{0}`")]
    EncodingError(#[from] ct_codecs::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for KeyAlgorithmError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Nested(nested) => nested.error_code(),
            _ => ErrorCode::BR_0063,
        }
    }
}
