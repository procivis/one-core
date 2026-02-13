//! Enumerates errors related to DID method provider.

use shared_types::DidValueError;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum DidMethodError {
    #[error("Could not resolve DID: `{0}`")]
    ResolutionError(String),
    #[error("Could not create DID: `{0}`")]
    CreationError(String),
    #[error("Could not deactivate DID: `{0}`")]
    CouldNotDeactivate(String),
    #[error("Did operation not supported")]
    OperationNotSupported,
    #[error("Did is deactivated")]
    Deactivated,
    #[error("Could not initialize: `{0}`")]
    InitializationError(String),

    #[error("JSON serialization error: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error("JSON serialization error: `{0}`")]
    JsonSyntax(#[from] json_syntax::SerializeError),
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error("Multihash error: `{0}`")]
    Multihash(#[from] multihash::Error),
    #[error("Hash error: `{0}`")]
    Hash(#[from] one_crypto::HasherError),
    #[error("URL parsing error: `{0}`")]
    URL(#[from] url::ParseError),
    #[error("Did value validation error: `{0}`")]
    DidValueError(#[from] DidValueError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for DidMethodError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Deactivated => ErrorCode::BR_0027,
            Self::CouldNotDeactivate(_) => ErrorCode::BR_0029,
            Self::ResolutionError(_) => ErrorCode::BR_0363,
            Self::DidValueError(_) => ErrorCode::BR_0364,
            Self::OperationNotSupported => ErrorCode::BR_0365,
            Self::Json(_)
            | Self::JsonSyntax(_)
            | Self::Encoding(_)
            | Self::Hash(_)
            | Self::Multihash(_)
            | Self::URL(_)
            | Self::InitializationError(_)
            | Self::CreationError(_) => ErrorCode::BR_0064,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DidMethodProviderError {
    #[error("JSON parse error: `{0}`")]
    JsonParse(#[from] serde_json::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for DidMethodProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::JsonParse(_) => ErrorCode::BR_0064,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
