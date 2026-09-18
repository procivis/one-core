use shared_types::IdentifierId;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::identifier_trust_information::SchemaFormat;
use crate::provider::ecosystem::model::{EcosystemRole, SchemaFilter};

#[derive(Debug, Error)]
pub enum EcosystemError {
    #[error("Missing identifier")]
    MissingIdentifier,
    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(IdentifierId),
    #[error("Disallowed schema: {0:?}")]
    DisallowedSchemaFormat(SchemaFormat),
    #[error("Unsupported role: `{0}`")]
    UnsupportedRole(EcosystemRole),
    #[error("Invalid ecosystem query: role `{role}` combined with `{filter}`")]
    InvalidRoleFilter {
        role: EcosystemRole,
        filter: SchemaFilter,
    },
    #[error("Untrusted identifier")]
    UntrustedIdentifier,
    #[error(transparent)]
    WalletAttestation(#[from] WalletAttestationRejection),

    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingIdentifier
            | Self::UntrustedIdentifier
            | Self::InvalidIdentifier(_)
            | Self::DisallowedSchemaFormat(_) => ErrorCode::BR_0477,
            Self::WalletAttestation(rejection) => rejection.error_code(),
            Self::UnsupportedRole(_) | Self::InvalidRoleFilter { .. } => ErrorCode::BR_0479,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Error)]
pub enum WalletAttestationRejection {
    #[error("Wallet Instance Attestation {0}")]
    WalletInstanceAttestation(RejectionReason),
    #[error("Key Attestation {0}")]
    KeyAttestation(RejectionReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RejectionReason {
    #[error("issuer not on wallet provider trust list")]
    IssuerUntrusted,
    #[error("is revoked")]
    Revoked,
    #[error("does not satisfy the required status period")]
    StatusPeriod,
}

impl ErrorCodeMixin for WalletAttestationRejection {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::WalletInstanceAttestation(reason) => match reason {
                RejectionReason::IssuerUntrusted => ErrorCode::BR_0494,
                RejectionReason::Revoked => ErrorCode::BR_0505,
                RejectionReason::StatusPeriod => ErrorCode::BR_0506,
            },
            Self::KeyAttestation(reason) => match reason {
                RejectionReason::IssuerUntrusted => ErrorCode::BR_0496,
                RejectionReason::Revoked => ErrorCode::BR_0499,
                RejectionReason::StatusPeriod => ErrorCode::BR_0507,
            },
        }
    }
}
