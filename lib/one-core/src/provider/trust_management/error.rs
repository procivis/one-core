use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustManagementError {
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("Mapping error: `{0}`")]
    MappingError(anyhow::Error),
    #[error("Failed to resolve did: `{0}`")]
    FailedToResolve(String),
}
