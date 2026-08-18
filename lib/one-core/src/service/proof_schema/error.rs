use shared_types::{ClaimSchemaId, OrganisationId, ProofSchemaId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum ProofSchemaServiceError {
    #[error("Proof schema `{0}` not found")]
    NotFound(ProofSchemaId),

    #[error("Missing parent claim schema for: `{0}`")]
    MissingParentClaimSchema(ClaimSchemaId),
    #[error("Missing claim schema: `{0}`")]
    MissingClaimSchema(ClaimSchemaId),
    #[error("Missing credential schema")]
    MissingCredentialSchema,
    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),

    #[error("Incorrect nested disclosure level")]
    IncorrectDisclosureLevel,
    #[error("Credential format {credential_format} does not support combined presentation")]
    InvalidCredentialCombination { credential_format: String },
    #[error("Nested claims in arrays cannot be requested")]
    NestedClaimInArrayRequested,
    #[error("Proof schema: Missing proof input schemas")]
    MissingProofInputSchemas,
    #[error("Proof schema: Claim schemas must not be empty")]
    MissingClaims,
    #[error("Proof schema: No required claim")]
    NoRequiredClaim,
    #[error("Proof schema: Duplicit claim schema")]
    DuplicitClaim,
    #[error("Sharing not supported for requested proof-schema")]
    SharingNotSupported,
    #[error("Duplicate proof input credential schema")]
    DuplicateProofInputCredentialSchema,

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for ProofSchemaServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0014,
            Self::MissingParentClaimSchema(_) => ErrorCode::BR_0109,
            Self::MissingClaimSchema(_) => ErrorCode::BR_0010,
            Self::MissingCredentialSchema => ErrorCode::BR_0009,
            Self::IncorrectDisclosureLevel => ErrorCode::BR_0130,
            Self::InvalidCredentialCombination { .. } => ErrorCode::BR_0305,
            Self::NestedClaimInArrayRequested => ErrorCode::BR_0125,
            Self::MissingProofInputSchemas => ErrorCode::BR_0104,
            Self::MissingClaims => ErrorCode::BR_0164,
            Self::NoRequiredClaim => ErrorCode::BR_0017,
            Self::DuplicitClaim => ErrorCode::BR_0018,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::SharingNotSupported => ErrorCode::BR_0163,
            Self::DuplicateProofInputCredentialSchema => ErrorCode::BR_0313,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
