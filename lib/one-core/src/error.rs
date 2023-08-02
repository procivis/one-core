use crate::{credential_formatter::FormatterError, data_layer::DataLayerError};

use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum OneCoreError {
    #[error("Data layer error: `{0}`")]
    DataLayerError(DataLayerError),
    #[error("SSI error: `{0}`")]
    SSIError(SSIError),
    #[error("Formatter error: `{0}`")]
    FormatterError(FormatterError),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SSIError {
    #[error("Already issued")]
    AlreadyIssued,
    #[error("Incorrect credential state")]
    IncorrectCredentialState,
    #[error("Incorrect proof state")]
    IncorrectProofState,
    #[error("Missing credential")]
    MissingCredential,
    #[error("Unsupported credential format")]
    UnsupportedCredentialFormat,
    #[error("Unsupported transport protocol")]
    UnsupportedTransportProtocol,
}
