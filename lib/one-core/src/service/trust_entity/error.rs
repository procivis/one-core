use shared_types::{
    DidId, DidValue, IdentifierId, OrganisationId, TrustAnchorId, TrustEntityId, TrustEntityKey,
};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::trust_management::error::TrustManagementError;

#[derive(thiserror::Error, Debug)]
pub enum TrustEntityServiceError {
    #[error("Trust entity `{0}` not found")]
    NotFound(TrustEntityId),
    #[error("Trust entity by entity key `{0}` not found")]
    NotFoundByEntityKey(TrustEntityKey),
    #[error("No trust entity found for the given did: {0}")]
    NotFoundForDid(DidId),
    #[error("trustAnchorId and entityId are already present")]
    AlreadyExists,

    #[error("Trust entity type not specified")]
    TypeNotSpecified,
    #[error("Trust entity has ambiguous ids specified")]
    AmbiguousIds,
    #[error("Invalid update request")]
    InvalidUpdateRequest,
    #[error("Trust anchor must be publish")]
    TrustAnchorMustBePublish,
    #[error("Trust anchor must be client")]
    TrustAnchorMustBeClient,
    #[error("Trust anchor is disabled")]
    TrustAnchorIsDisabled,
    #[error("Certificate `{certificate_id}` is not associated with identifier `{identifier_id}`")]
    IdentifierCertificateIdMismatch {
        identifier_id: String,
        certificate_id: String,
    },
    #[error("Incompatible DID type, reason: {reason}")]
    IncompatibleDidType { reason: String },
    #[error("Incompatible identifier type, reason: {reason}")]
    IncompatibleIdentifierType { reason: String },

    #[error("Trust anchor `{0}` not found")]
    MissingTrustAnchor(TrustAnchorId),
    #[error("Identifier `{0}` not found")]
    MissingIdentifier(IdentifierId),
    #[error("Identifier by did id `{0}` not found")]
    MissingIdentifierByDidId(DidId),
    #[error("Did `{0}` not found")]
    MissingDid(DidId),
    #[error("Did value `{0}` not found")]
    MissingDidValue(DidValue),
    #[error("Organisation `{0}` not found")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),
    #[error("Trust entity type does not match ids or content")]
    InvalidType,
    #[error("Trust entity subject key identifier does not match")]
    SubjectKeyIdentifierDoesNotMatch,
    #[error("Certificate id not specified")]
    CertificateIdNotSpecified,
    #[error("Trust entity has duplicates")]
    Duplicates,
    #[error("Multiple matching trust anchors")]
    MultipleMatchingTrustAnchors,

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("Forbidden")]
    Forbidden,
    #[error("Trust management error: `{0}`")]
    TrustManagementError(#[from] TrustManagementError),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TrustEntityServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) | Self::NotFoundByEntityKey(_) => ErrorCode::BR_0121,
            Self::NotFoundForDid(_) => ErrorCode::BR_0186,
            Self::AlreadyExists => ErrorCode::BR_0120,
            Self::AmbiguousIds => ErrorCode::BR_0228,
            Self::TypeNotSpecified => ErrorCode::BR_0229,
            Self::InvalidUpdateRequest => ErrorCode::BR_0181,
            Self::TrustAnchorMustBePublish => ErrorCode::BR_0123,
            Self::TrustAnchorMustBeClient => ErrorCode::BR_0188,
            Self::TrustAnchorIsDisabled => ErrorCode::BR_0187,
            Self::IncompatibleDidType { .. } => ErrorCode::BR_0025,
            Self::IncompatibleIdentifierType { .. } => ErrorCode::BR_0025,
            Self::InvalidType => ErrorCode::BR_0230,
            Self::Duplicates => ErrorCode::BR_0180,
            Self::MultipleMatchingTrustAnchors => ErrorCode::BR_0179,
            Self::SubjectKeyIdentifierDoesNotMatch => ErrorCode::BR_0231,
            Self::IdentifierCertificateIdMismatch { .. } | Self::CertificateIdNotSpecified => {
                ErrorCode::BR_0242
            }
            Self::MissingTrustAnchor(_) => ErrorCode::BR_0115,
            Self::MissingIdentifier(_) | Self::MissingIdentifierByDidId(_) => ErrorCode::BR_0207,
            Self::MissingDid(_) | Self::MissingDidValue(_) => ErrorCode::BR_0024,
            Self::MissingOrganisation(_) => ErrorCode::BR_0022,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Forbidden => ErrorCode::BR_0178,
            Self::TrustManagementError(_) => ErrorCode::BR_0185,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
