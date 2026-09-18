use standardized_types::openid4vp::dcql::{ClaimQuery, CredentialFormat, CredentialQueryId};
use thiserror::Error;

use super::AttestationCoverageSource;
use crate::config::core_config::IdentifierType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

mod mapper;
mod resolver;

#[derive(Debug, Clone, Error)]
pub(crate) enum QueryMismatchReason {
    #[error("Format mismatch, requested: `{0}`")]
    FormatMismatch(CredentialFormat),
    #[error("Claim mismatch, requested `{0:?}`")]
    ClaimMismatch(ClaimQuery),
    #[error("No claims requested")]
    NoClaimsRequested,
    #[error("No intended use declared")]
    NoIntendedUse,
}

#[derive(Debug, Error)]
pub(crate) enum HolderProofError {
    #[error("Missing registry URL")]
    MissingRegistryUrl,
    #[error(
        "The {document}'s intended use does not permit the requested credential `{query}`, reason: `{reason}`"
    )]
    DisallowedQuery {
        query: CredentialQueryId,
        document: AttestationCoverageSource,
        reason: QueryMismatchReason,
    },
    #[error("Missing identifier")]
    MissingIdentifier,
    #[error("Invalid identifier type: {0}")]
    InvalidIdentifierType(IdentifierType),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderProofError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingRegistryUrl | Self::MissingIdentifier | Self::InvalidIdentifierType(_) => {
                ErrorCode::BR_0477
            }
            Self::DisallowedQuery { .. } => ErrorCode::BR_0503,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
