use thiserror::Error;

use crate::config::ConfigValidationError;
use crate::config::core_config::KeyAlgorithmType;

#[derive(Debug, Error)]
pub enum WalletProviderError {
    #[error("Wallet provider not enabled in config: `{0}`")]
    WalletProviderDisabled(#[from] ConfigValidationError),
    #[error("Could not verify proof: `{0}`")]
    CouldNotVerifyProof(String),
    #[error("Key with algorith `{0}` not found`")]
    IssuerKeyWithAlgorithmNotFound(KeyAlgorithmType),
    #[error("Wallet unit revoked")]
    WalletUnitRevoked,
    #[error("Minimum refresh time not reached")]
    RefreshTimeNotReached,
    #[error("Invalid wallet unit attestation nonce")]
    InvalidWalletUnitAttestationNonce,
    #[error("Invalid wallet unit state")]
    InvalidWalletUnitState,
}
