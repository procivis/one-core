use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

pub(crate) mod dto;
pub(crate) mod importer;
pub(crate) mod parser;
pub mod transaction_code;

#[cfg(test)]
mod test;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0000,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
