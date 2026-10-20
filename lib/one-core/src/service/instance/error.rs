use shared_types::{InstanceId, OrganisationId, TrustCollectionId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum HolderInstanceError {
    #[error("Instance `{0}` already exists")]
    InstanceAlreadyExists(InstanceId),

    #[error(
        "App integrity check required: proof and public key must only be provided on wallet instance activation"
    )]
    AppIntegrityCheckRequired,

    #[error("App integrity check not required: provide proof and public key")]
    AppIntegrityCheckNotRequired,

    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),
    #[error("Invalid key algorithm: {0}")]
    InvalidKeyAlgorithm(String),
    #[error("No matching key storage configured: {0}")]
    NoMatchingKeyStorage(String),
    #[error("Invalid wallet provider url: {0}")]
    InvalidWalletProviderUrl(url::ParseError),
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Trust collection not found: {0}")]
    MissingTrustCollection(TrustCollectionId),
    #[error("Trust collections not in sync with remote")]
    TrustCollectionsNotInSync,

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("User authentication not configured for this wallet provider")]
    UserAuthenticationNotConfigured,

    #[error("User authentication not required")]
    UserAuthenticationNotRequired,

    #[error("User authentication required")]
    UserAuthenticationRequired,

    #[error("User authentication mandated but not supported for instances with OS WEB")]
    UserAuthenticationNotSupported,

    #[error("Wallet unit is not in pending state")]
    WalletUnitNotPending,

    #[error("Wallet unit registration expired, restart registration")]
    WalletUnitRegistrationExpired,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderInstanceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InstanceAlreadyExists(_) => ErrorCode::BR_0271,
            Self::AppIntegrityCheckRequired => ErrorCode::BR_0280,
            Self::AppIntegrityCheckNotRequired => ErrorCode::BR_0281,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            Self::NoMatchingKeyStorage(_) => ErrorCode::BR_0040,
            Self::InvalidWalletProviderUrl(_) => ErrorCode::BR_0295,
            Self::KeyAlreadyExists => ErrorCode::BR_0066,
            Self::MissingTrustCollection(_) => ErrorCode::BR_0391,
            Self::TrustCollectionsNotInSync => ErrorCode::BR_0407,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::UserAuthenticationNotConfigured => ErrorCode::BR_0449,
            Self::WalletUnitNotPending => ErrorCode::BR_0450,
            Self::UserAuthenticationNotRequired => ErrorCode::BR_0453,
            Self::UserAuthenticationRequired => ErrorCode::BR_0454,
            Self::UserAuthenticationNotSupported => ErrorCode::BR_0473,
            Self::WalletUnitRegistrationExpired => ErrorCode::BR_0455,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
