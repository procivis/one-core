use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletProviderClientError {
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
}
