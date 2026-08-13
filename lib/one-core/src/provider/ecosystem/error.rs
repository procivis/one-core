use shared_types::IdentifierId;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::identifier_trust_information::SchemaFormat;
use crate::provider::ecosystem::model::{EcosystemRole, SchemaFilter};

#[derive(Debug, Error)]
pub enum EcosystemError {
    #[error("Missing identifier")]
    MissingIdentifier,
    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(IdentifierId),
    #[error("Disallowed schema: {0:?}")]
    DisallowedSchemaFormat(SchemaFormat),
    #[error("Invalid ecosystem query: role `{role}` combined with `{filter}`")]
    InvalidRoleFilter {
        role: EcosystemRole,
        filter: SchemaFilter,
    },

    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingIdentifier
            | Self::InvalidIdentifier(_)
            | Self::DisallowedSchemaFormat(_) => ErrorCode::BR_0477,
            Self::InvalidRoleFilter { .. } => ErrorCode::BR_0479,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
