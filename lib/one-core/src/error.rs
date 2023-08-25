use thiserror::Error;

use crate::{
    credential_formatter::{FormatterError, ParseError},
    repository::error::DataLayerError,
    service::error::ServiceError,
    transport_protocol::TransportProtocolError,
};

#[derive(Debug, Error)]
pub enum OneCoreError {
    #[error("Data layer error: `{0}`")]
    DataLayerError(#[from] DataLayerError),
    #[error("Service error: `{0}`")]
    ServiceError(#[from] ServiceError),
    #[error("SSI error: `{0}`")]
    SSIError(#[from] SSIError),
    #[error("Formatter error: `{0}`")]
    FormatterError(#[from] FormatterError),
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
    ParseError(#[from] ParseError),
    #[error("Transport protocol error: `{0}`")]
    TransportProtocolError(#[from] TransportProtocolError),
    #[error("Unsupported credential format")]
    UnsupportedCredentialFormat,
    #[error("Unsupported transport protocol")]
    UnsupportedTransportProtocol,
}
