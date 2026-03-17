use shared_types::{IdentifierId, TrustEntryId, TrustListPublicationId, TrustListPublisherId};
use thiserror::Error;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType};
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::trust_list_role::TrustListRoleEnum;

#[derive(Debug, Error)]
pub enum TrustListPublicationServiceError {
    #[error("Missing provider for trust list `{0}`")]
    MissingTrustListProvider(TrustListPublisherId),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
    #[error("Identifier `{0}` not found")]
    IdentifierNotFound(IdentifierId),
    #[error("Unsupported identifier type `{0}`: expected one of `{1:?}`")]
    InvalidIdentifierType(IdentifierType, Vec<IdentifierType>),
    #[error("Selected key not matching supported types")]
    InvalidSelectedKey,
    #[error("Unsupported trust list publication role `{0:?}`: expected one of `{1:?}`")]
    InvalidTrustListRole(TrustListRoleEnum, Vec<TrustListRoleEnum>),
    #[error("Unknown key algorithm `{0}`")]
    UnknownKeyAlgorithm(String),
    #[error("Unsupported key type `{0}`: expected one of `{1:?}`")]
    InvalidKeyType(KeyAlgorithmType, Vec<KeyAlgorithmType>),
    #[error("Trust list publication `{0}` not found")]
    TrustListPublicationNotFound(TrustListPublicationId),
    #[error("Trust entry `{0}` not found")]
    TrustEntryNotFound(TrustEntryId),
    #[error("Content deserialization error: `{0}`")]
    ContentDeserialization(#[from] serde_json::Error),
    #[error("Identifier has to belong the same organisation as trust list")]
    OrganisationIdMismatch,
    #[error("Trust entry `{0}` doesn't belong to the trust list publication `{1}`")]
    TrustEntryNotInList(TrustEntryId, TrustListPublicationId),
}

impl ErrorCodeMixin for TrustListPublicationServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingTrustListProvider(_) => ErrorCode::BR_0388,
            Self::IdentifierNotFound(_) => ErrorCode::BR_0207,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::TrustEntryNotFound(_) => ErrorCode::BR_0387,
            Self::Nested(nested) => nested.error_code(),
            Self::ContentDeserialization(_) => ErrorCode::BR_0189,
            Self::InvalidIdentifierType(_, _) => ErrorCode::BR_0382,
            Self::InvalidSelectedKey => ErrorCode::BR_0330,
            Self::InvalidTrustListRole(_, _) => ErrorCode::BR_0386,
            Self::UnknownKeyAlgorithm(_) => ErrorCode::BR_0043,
            Self::InvalidKeyType(_, _) => ErrorCode::BR_0389,
            Self::TrustListPublicationNotFound(_) => ErrorCode::BR_0383,
            Self::OrganisationIdMismatch => ErrorCode::BR_0285,
            Self::TrustEntryNotInList(_, _) => ErrorCode::BR_0390,
        }
    }
}
