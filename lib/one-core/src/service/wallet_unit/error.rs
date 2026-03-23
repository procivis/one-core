use shared_types::{HolderWalletUnitId, OrganisationId, TrustCollectionId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum HolderWalletUnitError {
    #[error("Wallet unit revoked")]
    WalletUnitRevoked,
    #[error("Wallet unit `{0}` already exists")]
    WalletUnitAlreadyExists(HolderWalletUnitId),

    #[error(
        "App integrity check required: proof and public key must only be provided on wallet unit activation"
    )]
    AppIntegrityCheckRequired,

    #[error("App integrity check not required: provide proof and public key")]
    AppIntegrityCheckNotRequired,

    #[error("Holder wallet unit `{0}` not found")]
    HolderWalletUnitNotFound(HolderWalletUnitId),
    #[error("Organisation `{0}` not found")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),
    #[error("Invalid key algorithm: {0}")]
    InvalidKeyAlgorithm(String),
    #[error("Invalid wallet provider url: {0}")]
    InvalidWalletProviderUrl(url::ParseError),
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Trust collection not found: {0}")]
    MissingTrustCollection(TrustCollectionId),

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderWalletUnitError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::WalletUnitRevoked => ErrorCode::BR_0261,
            Self::WalletUnitAlreadyExists(_) => ErrorCode::BR_0271,
            Self::AppIntegrityCheckRequired => ErrorCode::BR_0280,
            Self::AppIntegrityCheckNotRequired => ErrorCode::BR_0281,
            Self::HolderWalletUnitNotFound(_) => ErrorCode::BR_0296,
            Self::MissingOrganisation(_) => ErrorCode::BR_0022,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            Self::InvalidWalletProviderUrl(_) => ErrorCode::BR_0295,
            Self::KeyAlreadyExists => ErrorCode::BR_0066,
            Self::MissingTrustCollection(_) => ErrorCode::BR_0391,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
