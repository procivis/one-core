//! Enumerates errors related to key storage provider.

use one_crypto::SignerError;
use one_crypto::encryption::EncryptionError;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::key_storage::model::Features;

#[derive(Debug, Error)]
pub enum KeyStorageProviderError {
    #[error("Invalid key storage `{0}`")]
    InvalidKeyStorage(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for KeyStorageProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidKeyStorage(_) => ErrorCode::BR_0040,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Error)]
pub enum KeyStorageError {
    #[error("Key storage error: `{0}`")]
    Failed(String),
    #[error("Invalid key algorithm `{0}`")]
    InvalidKeyAlgorithm(String),
    #[error("Not supported for type: `{0}`")]
    NotSupported(String),
    #[error("Unsupported key type: {key_type}")]
    UnsupportedKeyType { key_type: String },
    #[error("Unsupported feature: `{feature}`")]
    UnsupportedFeature { feature: Features },

    #[error("Encryption error: `{0}`")]
    Encryption(#[from] EncryptionError),
    #[error("Signer error: `{0}`")]
    SignerError(#[from] SignerError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for KeyStorageError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Nested(nested) => nested.error_code(),
            Self::NotSupported(_)
            | Self::UnsupportedKeyType { .. }
            | Self::UnsupportedFeature { .. } => ErrorCode::BR_0361,
            _ => ErrorCode::BR_0039,
        }
    }
}
