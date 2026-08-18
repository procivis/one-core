use shared_types::{OrganisationId, TrustCollectionId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum OrganisationServiceError {
    #[error("Organisation already exists")]
    AlreadyExists,
    #[error("Trust collection `{0}` not found")]
    MissingTrustCollection(TrustCollectionId),
    #[error("Trust collections are not in sync with the wallet provider")]
    TrustCollectionsNotInSync,
    #[error("Trust collections must all belong to the same provider (wallet or verifier)")]
    TrustCollectionsSpanMultipleProviders,
    #[error("Ecosystem enforcement is mandated by the organisation's provider")]
    EcosystemEnforcementMandated,

    #[error("Identifier does not belong to this organisation")]
    IdentifierOrganisationMismatch,
    #[error("Wallet provider is already associated to organisation `{0}`")]
    WalletProviderAlreadyAssociated(OrganisationId),
    #[error("Verifier provider is already associated to organisation `{0}`")]
    VerifierProviderAlreadyAssociated(OrganisationId),
    #[error("Invalid verifier provider")]
    VerifierProviderNotConfigured,
    #[error("Invalid parent organisation")]
    InvalidParentOrganisation,
    #[error("Parent organisation `{0}` not found")]
    ParentOrganisationNotFound(OrganisationId),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for OrganisationServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::AlreadyExists => ErrorCode::BR_0023,
            Self::MissingTrustCollection(_) => ErrorCode::BR_0391,
            Self::TrustCollectionsNotInSync => ErrorCode::BR_0407,
            Self::TrustCollectionsSpanMultipleProviders => ErrorCode::BR_0472,
            Self::EcosystemEnforcementMandated => ErrorCode::BR_0481,
            Self::IdentifierOrganisationMismatch => ErrorCode::BR_0285,
            Self::WalletProviderAlreadyAssociated(_) => ErrorCode::BR_0283,
            Self::VerifierProviderAlreadyAssociated(_) => ErrorCode::BR_0465,
            Self::VerifierProviderNotConfigured => ErrorCode::BR_0466,
            Self::InvalidParentOrganisation => ErrorCode::BR_0419,
            Self::ParentOrganisationNotFound(_) => ErrorCode::BR_0022,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
