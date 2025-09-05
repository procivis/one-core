use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletProviderClientError {
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("Integrity check required")]
    IntegrityCheckRequired,
    #[error("Integrity check not required")]
    IntegrityCheckNotRequired,
}
