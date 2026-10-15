use shared_types::OrganisationId;

use crate::config::core_config::IdentifierType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::instance::InstanceRole;

#[derive(thiserror::Error, Debug)]
pub enum OrganisationServiceError {
    #[error("Organisation already exists")]
    AlreadyExists,
    #[error("Ecosystem enforcement is mandated by the organisation's provider")]
    EcosystemEnforcementMandated,

    #[error("Identifier does not belong to this organisation")]
    IdentifierOrganisationMismatch,
    #[error("Provider is already associated to organisation `{0}` for role: {1}")]
    ProviderAlreadyAssociated(OrganisationId, InstanceRole),
    #[error("Invalid parent organisation")]
    InvalidParentOrganisation,
    #[error("Invalid identifier type: {0}")]
    InvalidIdentifierType(IdentifierType),
    #[error("Parent organisation `{0}` not found")]
    ParentOrganisationNotFound(OrganisationId),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for OrganisationServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::AlreadyExists => ErrorCode::BR_0023,
            Self::EcosystemEnforcementMandated => ErrorCode::BR_0481,
            Self::IdentifierOrganisationMismatch => ErrorCode::BR_0285,
            Self::ProviderAlreadyAssociated(_, InstanceRole::Wallet) => ErrorCode::BR_0283,
            Self::ProviderAlreadyAssociated(_, InstanceRole::Verifier) => ErrorCode::BR_0465,
            Self::InvalidParentOrganisation => ErrorCode::BR_0419,
            Self::InvalidIdentifierType(_) => ErrorCode::BR_0323,
            Self::ParentOrganisationNotFound(_) => ErrorCode::BR_0022,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
