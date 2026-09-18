use thiserror::Error;

use super::AttestationCoverageSource;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

mod credential;
mod metadata;

#[derive(Debug, Error)]
pub(crate) enum HolderIssuanceError {
    #[error("Missing registry URL")]
    MissingRegistryUrl,
    #[error("Missing identifier")]
    MissingIdentifier,
    #[error("The {document} does not cover the requested credential")]
    TrustAttestationDoesNotCoverCredential { document: AttestationCoverageSource },
    #[error("Inconsistent trust info")]
    InconsistentTrustInfo,
    #[error("No credential configuration")]
    NoCredentialConfiguration,
    #[error("Invalid credential configuration: `{0}`")]
    InvalidCredentialConfiguration(String),

    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderIssuanceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingRegistryUrl
            | Self::MissingIdentifier
            | Self::InconsistentTrustInfo
            | Self::NoCredentialConfiguration
            | Self::InvalidCredentialConfiguration(_) => ErrorCode::BR_0477,
            Self::TrustAttestationDoesNotCoverCredential { .. } => ErrorCode::BR_0490,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
