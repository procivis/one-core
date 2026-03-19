use shared_types::{OrganisationId, TrustCollectionId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum TrustCollectionServiceError {
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
    #[error("Missing organisation: {0}")]
    MissingOrganisation(OrganisationId),
    #[error("Trust collection already exists")]
    AlreadyExists,
    #[error("Trust collection not found")]
    NotFound(TrustCollectionId),
}

impl ErrorCodeMixin for TrustCollectionServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::AlreadyExists => ErrorCode::BR_0398,
            Self::NotFound(_) => ErrorCode::BR_0391,
        }
    }
}
