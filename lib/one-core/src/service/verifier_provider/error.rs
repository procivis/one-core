use shared_types::TrustCollectionId;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerifierProviderError {
    #[error("Trust collection `{0}` not found")]
    MissingTrustCollection(TrustCollectionId),

    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerifierProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingTrustCollection(_) => ErrorCode::BR_0391,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
