use shared_types::TrustCollectionId;
use thiserror::Error;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::instance::InstanceRole;

#[derive(Debug, Error)]
pub enum ManagedInstanceError {
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
    #[error("Verifier provider not associated with any organisation")]
    VerifierProviderNotAssociatedWithOrganisation,
    #[error("Invalid verifier provider")]
    VerifierProviderNotConfigured,
    #[error("Verifier provider organisation disabled")]
    VerifierProviderOrganisationDisabled,
    #[error("Wallet unit must be active")]
    WalletUnitMustBeActive,
    #[error("Wallet unit must be pending")]
    WalletUnitMustBePending,
    #[error("Insufficient security level")]
    InsufficientSecurityLevel,
    #[error("Trust collection `{0}` not found")]
    MissingTrustCollection(TrustCollectionId),
    #[error("User ID token not expected: userAuthentication not configured")]
    UserIdTokenNotExpected,
    #[error("User ID token required but not provided")]
    MissingUserIdToken,
    #[error("Invalid user ID token: {0}")]
    InvalidUserIdToken(String),
    #[error("Missing wallet unit attestation")]
    MissingWalletUnitAttestation,
    #[error("Invalid role: {0}")]
    InvalidRole(InstanceRole),
    #[error("User access token required but not provided")]
    MissingUserAccessToken,
    #[error("User authentication mandated but not supported for instances with OS WEB")]
    UserAuthenticationNotSupported,

    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for ManagedInstanceError {
    fn error_code(&self) -> ErrorCode {
        match self {
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
            Self::VerifierProviderNotConfigured | Self::VerifierProviderOrganisationDisabled => {
                ErrorCode::BR_0470
            }
            Self::VerifierProviderNotAssociatedWithOrganisation => ErrorCode::BR_0471,
            Self::WalletUnitMustBeActive => ErrorCode::BR_0081,
            Self::WalletUnitMustBePending => ErrorCode::BR_0168,
            Self::InsufficientSecurityLevel => ErrorCode::BR_0297,
            Self::MissingTrustCollection(_) => ErrorCode::BR_0391,
            Self::UserIdTokenNotExpected => ErrorCode::BR_0446,
            Self::MissingUserIdToken => ErrorCode::BR_0447,
            Self::InvalidUserIdToken(_) => ErrorCode::BR_0448,
            Self::InvalidRole(_) => ErrorCode::BR_0467,
            Self::MissingUserAccessToken => ErrorCode::BR_0469,
            Self::UserAuthenticationNotSupported => ErrorCode::BR_0473,
            Self::MissingWalletUnitAttestation => ErrorCode::BR_0451,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
