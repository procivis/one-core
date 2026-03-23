use shared_types::{
    OrganisationId, TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId,
};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Debug, Error)]
pub enum TrustCollectionServiceError {
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
    #[error("Missing organisation: {0}")]
    MissingOrganisation(OrganisationId),
    #[error("Trust collection already exists")]
    TrustCollectionAlreadyExists,
    #[error("Trust collection `{0}` not found: {0}")]
    TrustCollectionNotFound(TrustCollectionId),
    #[error("Trust list subscription `{0}` not found")]
    TrustListSubscriptionNotFound(TrustListSubscriptionId),
    #[error("Missing provider for trust list `{0}`")]
    MissingTrustListSubscriber(TrustListSubscriberId),
    #[error("Unsupported trust list subscription role `{0:?}`: expected one of `{1:?}`")]
    InvalidTrustListRole(TrustListRoleEnum, Vec<TrustListRoleEnum>),
    #[error("Trust list subscription already exists")]
    TrustListSubscriptionAlreadyExists,
}

impl ErrorCodeMixin for TrustCollectionServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::TrustCollectionAlreadyExists => ErrorCode::BR_0398,
            Self::TrustCollectionNotFound(_) => ErrorCode::BR_0391,
            Self::MissingTrustListSubscriber(_) => ErrorCode::BR_0400,
            Self::InvalidTrustListRole(_, _) => ErrorCode::BR_0386,
            Self::TrustListSubscriptionNotFound(_) => ErrorCode::BR_0402,
            Self::TrustListSubscriptionAlreadyExists => ErrorCode::BR_0403,
        }
    }
}
