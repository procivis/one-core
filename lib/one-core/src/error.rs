use thiserror::Error;

use crate::{
    credential_formatter::{FormatterError, ParseError},
    data_layer::DataLayerError,
    transport_protocol::TransportProtocolError,
};

#[derive(Debug, Error)]
pub enum OneCoreError {
    #[error("Data layer error: `{0}`")]
    DataLayerError(DataLayerError),
    #[error("SSI error: `{0}`")]
    SSIError(SSIError),
    #[error("Formatter error: `{0}`")]
    FormatterError(FormatterError),
}

#[derive(Debug, Error)]
pub enum SSIError {
    #[error("Already issued")]
    AlreadyIssued,
    #[error("Incorrect credential state")]
    IncorrectCredentialState,
    #[error("Incorrect parameters: `{0}`")]
    IncorrectParameters(String),
    #[error("Incorrect proof state")]
    IncorrectProofState,
    #[error("Incorrect proof")]
    IncorrectProof,
    #[error("Missing credential")]
    MissingCredential,
    #[error("Missing proof")]
    MissingProof,
    #[error("Parse error: `{0}`")]
    ParseError(ParseError),
    #[error("Transport protocol error: `{0}`")]
    TransportProtocolError(TransportProtocolError),
    #[error("Unsupported credential format")]
    UnsupportedCredentialFormat,
    #[error("Unsupported transport protocol")]
    UnsupportedTransportProtocol,
}

impl From<SSIError> for OneCoreError {
    fn from(value: SSIError) -> Self {
        OneCoreError::SSIError(value)
    }
}

impl From<FormatterError> for OneCoreError {
    fn from(value: FormatterError) -> Self {
        OneCoreError::FormatterError(value)
    }
}

impl From<DataLayerError> for OneCoreError {
    fn from(value: DataLayerError) -> Self {
        OneCoreError::DataLayerError(value)
    }
}
