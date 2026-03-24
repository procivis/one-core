use shared_types::{OrganisationId, TrustCollectionId, VerifierInstanceId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerifierInstanceServiceError {
    #[error("Verifier instance `{0}` already exists")]
    VerifierInstanceAlreadyExists(VerifierInstanceId),

    #[error("Organisation `{0}` not found")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),
    #[error("Invalid verifier provider url: {0}")]
    InvalidProviderUrl(url::ParseError),
    #[error("Trust collection not found: {0}")]
    MissingTrustCollection(TrustCollectionId),
    #[error("Trust collections not in sync with remote")]
    TrustCollectionsNotInSync,

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerifierInstanceServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::VerifierInstanceAlreadyExists(_) => ErrorCode::BR_0271,
            Self::MissingOrganisation(_) => ErrorCode::BR_0022,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::InvalidProviderUrl(_) => ErrorCode::BR_0295,
            Self::MissingTrustCollection(_) => ErrorCode::BR_0391,
            Self::TrustCollectionsNotInSync => ErrorCode::BR_0407,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
