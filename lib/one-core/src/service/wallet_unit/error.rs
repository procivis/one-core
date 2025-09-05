use thiserror::Error;

use crate::provider::wallet_provider_client::error::WalletProviderClientError;

#[derive(Debug, Error)]
pub enum WalletUnitAttestationError {
    #[error("Wallet unit revoked")]
    WalletUnitRevoked,

    #[error("Wallet unit client failure: {0}")]
    WalletProviderClientFailure(#[from] WalletProviderClientError),

    #[error(
        "App integrity check required: proof and public key must only be provided on wallet unit activation"
    )]
    AppIntegrityCheckRequired,

    #[error("App integrity check not required: provide proof and public key")]
    AppIntegrityCheckNotRequired,
}
