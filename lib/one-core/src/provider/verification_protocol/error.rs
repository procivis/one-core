use dcql::DcqlError;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerificationProtocolError {
    #[error("Verification protocol failure: `{0}`")]
    Failed(String),
    #[error("Verification protocol disabled: `{0}`")]
    Disabled(String),
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Invalid request: `{0}`")]
    InvalidDcqlQueryOrPresentationDefinition(String),
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    StorageAccessError(anyhow::Error),
    #[error("DCQL error: `{0}`")]
    DcqlError(DcqlError),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerificationProtocolError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Failed(_) => ErrorCode::BR_0062,
            Self::Transport(_) => ErrorCode::BR_0086,
            Self::JsonError(_) => ErrorCode::BR_0062,
            Self::OperationNotSupported => ErrorCode::BR_0062,
            Self::InvalidRequest(_) => ErrorCode::BR_0085,
            Self::Disabled(_) => ErrorCode::BR_0085,
            Self::Other(_) => ErrorCode::BR_0062,
            Self::StorageAccessError(_) => ErrorCode::BR_0062,
            Self::InvalidDcqlQueryOrPresentationDefinition(_) => ErrorCode::BR_0083,
            Self::DcqlError(_) => ErrorCode::BR_0085,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
