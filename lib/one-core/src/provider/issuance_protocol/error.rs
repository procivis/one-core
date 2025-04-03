use thiserror::Error;

#[derive(Debug, Error)]
pub enum IssuanceProtocolError {
    #[error("Issuance protocol failure: `{0}`")]
    Failed(String),
    #[error("Issuance protocol disabled: `{0}`")]
    Disabled(String),
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Base url is unknown")]
    MissingBaseUrl,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Incorrect credential schema type")]
    IncorrectCredentialSchemaType,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    StorageAccessError(anyhow::Error),
    #[error(transparent)]
    TxCode(TxCodeError),
    #[error("Credential offer issuer did does not match credential issuer did")]
    DidMismatch,
    #[error("Credential signature verification failed: `{0}`")]
    CredentialVerificationFailed(anyhow::Error),
}

#[derive(Debug, Error)]
pub enum TxCodeError {
    #[error("Incorrect tx_code")]
    IncorrectCode,
    #[error("Invalid use of tx_code")]
    InvalidCodeUse,
}
