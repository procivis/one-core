use thiserror::Error;

use crate::config::validator::datatype::DatatypeValidationError;

pub mod datatype;
pub mod did;
pub mod exchange;
pub mod format;
pub mod revocation;

#[derive(Debug, PartialEq, Error)]
pub enum ConfigValidationError {
    // general
    #[error("Mismatched value type and params type")]
    MismatchedValueTypeAndParamsType,
    #[error("Key not found: `{0}`")]
    KeyNotFound(String),
    #[error("Unknown type: `{0}`")]
    UnknownType(String),
    #[error("Unparsed parameter tree")]
    UnparsedParameterTree,

    #[error("Datatype validation error: `{0}`")]
    DatatypeValidationError(#[from] DatatypeValidationError),
}
