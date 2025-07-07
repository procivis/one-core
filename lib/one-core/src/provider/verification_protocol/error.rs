use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationProtocolError {
    #[error("Verification protocol failure: `{0}`")]
    Failed(String),
    #[error("Verification protocol disabled: `{0}`")]
    Disabled(String),
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Invalid request: `{0}`")]
    InvalidDcqlQueryOrPresentationDefinition(String),
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    StorageAccessError(anyhow::Error),
}
