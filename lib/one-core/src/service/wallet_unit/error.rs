use thiserror::Error;

use crate::provider::wallet_provider_client::error::WalletProviderClientError;

#[derive(Debug, Error)]
pub enum WalletUnitAttestationError {
    #[error("Wallet unit revoked")]
    WalletUnitRevoked,

    #[error("Wallet unit client failure: {0}")]
    WalletProviderClientFailure(#[from] WalletProviderClientError),
}
