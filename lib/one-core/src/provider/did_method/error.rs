//! Enumerates errors related to DID method provider.

use shared_types::{DidId, KeyId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DidMethodError {
    #[error("Key algorithm not found")]
    KeyAlgorithmNotFound,
    #[error("Could not resolve: `{0}`")]
    ResolutionError(String),
    #[error("Could not create: `{0}`")]
    CouldNotCreate(String),
    #[error("Could not deactivate: `{0}`")]
    CouldNotDeactivate(String),
    #[error("Not supported")]
    NotSupported,
    #[error("Did value validation error")]
    ValidationError,
    #[error("Did is deactivated")]
    Deactivated,
    #[error("Mapping error: `{0}`")]
    MappingError(String),
}

#[derive(Debug, Error)]
pub enum DidMethodProviderError {
    #[error("Did method error: `{0}`")]
    DidMethod(#[from] DidMethodError),
    #[error("Failed to resolve did: `{0}`")]
    FailedToResolve(String),
    #[error("Missing did method name in did value")]
    MissingDidMethodNameInDidValue,
    #[error("Missing did provider: `{0}`")]
    MissingProvider(String),

    #[error("Verification method id of key `{key_id}` not found in did document for did '{did_id}")]
    VerificationMethodIdNotFound { key_id: KeyId, did_id: DidId },

    #[error("Other: `{0}`")]
    Other(String),

    #[error("JSON parse error: `{0}`")]
    JsonParse(#[from] serde_json::Error),
    #[error("Did value validation error")]
    DidValueValidationError,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for DidMethodProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::DidMethod(_)
            | Self::FailedToResolve(_)
            | Self::JsonParse(_)
            | Self::MissingDidMethodNameInDidValue
            | Self::VerificationMethodIdNotFound { .. }
            | Self::DidValueValidationError
            | Self::Other(_) => ErrorCode::BR_0064,
            Self::MissingProvider(_) => ErrorCode::BR_0031,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
