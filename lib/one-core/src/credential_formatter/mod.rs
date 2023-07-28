use crate::data_layer::data_model::DetailCredentialResponse;

// Implementations
pub mod jwt_formatter;

use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum FormatterError {
    #[error("Failed: `{0}`")]
    Failed(String),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not format: `{0}`")]
    CouldNotFormat(String),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Failed: `{0}`")]
    Failed(String),
}

// This is just a proposition.
// Will be  developed in future.
pub trait CredentialFormatter {
    fn format(
        &self,
        credentials: &DetailCredentialResponse,
        holder_did: &str,
    ) -> Result<String, FormatterError>;
}
