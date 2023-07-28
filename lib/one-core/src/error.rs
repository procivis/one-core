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
    #[error("Incorrect parameters")]
    IncorrectParameters,
    #[error("Incorrect proof state")]
    IncorrectProofState,
    #[error("Missing credential")]
    MissingCredential,
    #[error("Parse error: `{0}`")]
    ParseError(ParseError),
    #[error("Incorrect query parameters: `{0}`")]
    QueryRejection(axum::extract::rejection::QueryRejection),
    #[error("Transport protocol error: `{0}`")]
    TransportProtocolError(TransportProtocolError),
    #[error("Unsupported credential format")]
    UnsupportedCredentialFormat,
    #[error("Unsupported transport protocol")]
    UnsupportedTransportProtocol,
}
