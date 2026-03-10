use shared_types::{CredentialId, DidId, IdentifierId, InteractionId, OrganisationId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum HolderServiceError {
    #[error("Incompatible holder identifier")]
    IncompatibleHolderIdentifier,
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Invalid identifier input: {0}")]
    InvalidIdentifierInput(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Missing proof for interaction `{0}`")]
    MissingProofForInteraction(InteractionId),
    #[error("Missing credentials for interaction: `{0}`")]
    MissingCredentialsForInteraction(InteractionId),
    #[error("Missing exchange protocol `{0}`")]
    MissingExchangeProtocol(String),
    #[error("Credential `{0}` not found")]
    MissingCredential(CredentialId),
    #[error("Did `{0}` not found")]
    MissingDid(DidId),
    #[error("Identifier `{0}` not found")]
    MissingIdentifier(IdentifierId),
    #[error("Interaction `{0}` not found")]
    MissingInteraction(InteractionId),
    #[error("Missing organisation: {0}")]
    MissingOrganisation(OrganisationId),
    #[error("Missing credentials for credential: {credential_id}")]
    MissingCredentialData { credential_id: CredentialId },
    #[error("Presentation submission must contain at least one credential")]
    EmptyPresentationSubmission,
    #[error("Invalid presentation submission: {reason}")]
    InvalidPresentationSubmission { reason: String },
    #[error("No suitable transport found for exchange")]
    TransportNotAllowedForExchange,
    #[error("Incompatible holder key algorithm")]
    IncompatibleHolderKeyAlgorithm,
    #[error("Incompatible holder did method")]
    IncompatibleHolderDidMethod,
    #[error("Rejection not supported")]
    RejectionNotSupported,
    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),

    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidKey(_) => ErrorCode::BR_0096,
            Self::InvalidIdentifierInput(_) => ErrorCode::BR_0217,
            Self::IncompatibleHolderKeyAlgorithm
            | Self::IncompatibleHolderIdentifier
            | Self::IncompatibleHolderDidMethod => ErrorCode::BR_0218,
            Self::MissingProofForInteraction(_) => ErrorCode::BR_0094,
            Self::MissingCredentialsForInteraction(_) => ErrorCode::BR_0004,
            Self::MissingExchangeProtocol(_) => ErrorCode::BR_0046,
            Self::EmptyPresentationSubmission => ErrorCode::BR_0246,
            Self::MissingCredential(_) => ErrorCode::BR_0001,
            Self::MissingCredentialData { .. } => ErrorCode::BR_0005,
            Self::InvalidPresentationSubmission { .. } => ErrorCode::BR_0291,
            Self::TransportNotAllowedForExchange => ErrorCode::BR_0160,
            Self::MissingDid(_) => ErrorCode::BR_0024,
            Self::InvalidInput(_) => ErrorCode::BR_0323,
            Self::MissingIdentifier(_) => ErrorCode::BR_0207,
            Self::MissingInteraction(_) => ErrorCode::BR_0257,
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::RejectionNotSupported => ErrorCode::BR_0237,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
