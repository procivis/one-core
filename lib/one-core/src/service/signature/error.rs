use thiserror::Error;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum SignatureServiceError {
    #[error("Missing provider for signature type `{0}`")]
    MissingSignerProvider(String),
    #[error("Invalid signature id {0}")]
    InvalidSignatureId(Uuid),
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for SignatureServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingSignerProvider { .. } => ErrorCode::BR_0326,
            Self::InvalidSignatureId(_) => ErrorCode::BR_0327,
            Self::MappingError(_) => ErrorCode::BR_0000,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
