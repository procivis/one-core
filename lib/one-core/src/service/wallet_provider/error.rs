use thiserror::Error;

use crate::config::ConfigValidationError;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};

#[derive(Debug, Error)]
pub enum WalletProviderError {
    #[error("Wallet provider not enabled in config: `{0}`")]
    WalletProviderDisabled(#[from] ConfigValidationError),
    #[error("Missing proof")]
    MissingProof,
    #[error("Missing publicKey")]
    MissingPublicKey,
    #[error("Could not verify proof: `{0}`")]
    CouldNotVerifyProof(String),
    #[error("Key with algorithm `{0}` not found`")]
    IssuerKeyWithAlgorithmNotFound(KeyAlgorithmType),
    #[error("Wallet unit revoked")]
    WalletUnitRevoked,
    #[error("Minimum refresh time not reached")]
    RefreshTimeNotReached,
    #[error("Missing wallet unit attestation nonce")]
    MissingWalletUnitAttestationNonce,
    #[error("Invalid wallet unit attestation nonce")]
    InvalidWalletUnitAttestationNonce,
    #[error("Invalid wallet unit state")]
    InvalidWalletUnitState,
    #[error("Failed to validate app integrity: {0}")]
    AppIntegrityValidationError(String),
    #[error("App integrity check required")]
    AppIntegrityCheckRequired,
    #[error("App integrity check not required")]
    AppIntegrityCheckNotRequired,
    #[error("Wallet unit already exists")]
    WalletUnitAlreadyExists,
    #[error("Wallet provider not associated with any organisation")]
    WalletProviderNotAssociatedWithOrganisation,
    #[error("Invalid wallet provider")]
    WalletProviderNotConfigured,
    #[error("Wallet provider organisation disabled")]
    WalletProviderOrganisationDisabled,
    #[error("Wallet unit must be active")]
    WalletUnitMustBeActive,
    #[error("Wallet unit must be pending")]
    WalletUnitMustBePending,
    #[error("Insufficient security level")]
    InsufficientSecurityLevel,
}

impl ErrorCodeMixin for WalletProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::WalletProviderDisabled(_) => ErrorCode::BR_0260,
            Self::CouldNotVerifyProof(_) => ErrorCode::BR_0071,
            Self::IssuerKeyWithAlgorithmNotFound(_) => ErrorCode::BR_0222,
            Self::WalletUnitRevoked => ErrorCode::BR_0261,
            Self::RefreshTimeNotReached => ErrorCode::BR_0258,
            Self::MissingWalletUnitAttestationNonce | Self::InvalidWalletUnitAttestationNonce => {
                ErrorCode::BR_0153
            }
            Self::InvalidWalletUnitState => ErrorCode::BR_0265,
            Self::AppIntegrityValidationError(_) => ErrorCode::BR_0266,
            Self::MissingProof => ErrorCode::BR_0268,
            Self::MissingPublicKey => ErrorCode::BR_0269,
            Self::AppIntegrityCheckRequired => ErrorCode::BR_0270,
            Self::WalletUnitAlreadyExists => ErrorCode::BR_0271,
            Self::AppIntegrityCheckNotRequired => ErrorCode::BR_0279,
            Self::WalletProviderNotConfigured | Self::WalletProviderOrganisationDisabled => {
                ErrorCode::BR_0284
            }
            Self::WalletProviderNotAssociatedWithOrganisation => ErrorCode::BR_0286,
            Self::WalletUnitMustBeActive => ErrorCode::BR_0081,
            Self::WalletUnitMustBePending => ErrorCode::BR_0168,
            Self::InsufficientSecurityLevel => ErrorCode::BR_0297,
        }
    }
}
