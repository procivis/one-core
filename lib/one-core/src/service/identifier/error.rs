use shared_types::{IdentifierId, KeyId, OrganisationId};

use crate::config::core_config::IdentifierType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum IdentifierServiceError {
    #[error("Identifier `{0}` not found")]
    NotFound(IdentifierId),
    #[error("Identifier type `{0}` disabled")]
    IdentifierTypeDisabled(IdentifierType),
    #[error(
        "DID, Key, Certificate or Certificate Authority must be specified when creating identifier"
    )]
    InvalidCreationInput,

    #[error("Organisation `{0}` not found")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation `{0}` is deactivated")]
    OrganisationDeactivated(OrganisationId),
    #[error("Key `{0}` not found")]
    MissingKey(KeyId),

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for IdentifierServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0207,
            Self::IdentifierTypeDisabled(_) => ErrorCode::BR_0227,
            Self::InvalidCreationInput => ErrorCode::BR_0206,
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::OrganisationDeactivated(_) => ErrorCode::BR_0241,
            Self::MissingKey(_) => ErrorCode::BR_0037,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
