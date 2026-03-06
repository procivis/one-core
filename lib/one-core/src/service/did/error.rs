use shared_types::{DidId, KeyId, OrganisationId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum DidServiceError {
    #[error("Did `{0}` not found")]
    NotFound(DidId),
    #[error("Invalid DID method: {method}")]
    InvalidMethod { method: String },
    #[error("DID {0} is deactivated")]
    Deactivated(DidId),

    #[error("Organisation `{0}` not found")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation `{0}` is deactivated")]
    OrganisationDeactivated(OrganisationId),
    #[error("Key `{0}` not found")]
    MissingKey(KeyId),

    #[error("DID {method} already has the same value `{value}` for deactivated field")]
    DeactivatedSameValue { value: bool, method: String },
    #[error("DID method {method} cannot be deactivated")]
    CannotBeDeactivated { method: String },
    #[error("DID method {method} cannot be reactivated")]
    CannotBeReactivated { method: String },
    #[error("Remote DID cannot be deactivated")]
    RemoteDid,

    #[error("DID: Invalid key number")]
    InvalidNumberOfKeys,
    #[error("Key storage `{0}` invalid")]
    InvalidKeyStorage(String),

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for DidServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0024,
            Self::InvalidMethod { .. } => ErrorCode::BR_0026,
            Self::Deactivated(_) | Self::DeactivatedSameValue { .. } => ErrorCode::BR_0027,
            Self::CannotBeDeactivated { .. } | Self::RemoteDid => ErrorCode::BR_0029,
            Self::CannotBeReactivated { .. } => ErrorCode::BR_0256,
            Self::InvalidNumberOfKeys => ErrorCode::BR_0030,
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::OrganisationDeactivated(_) => ErrorCode::BR_0241,
            Self::MissingKey(_) => ErrorCode::BR_0037,
            Self::InvalidKeyStorage(_) => ErrorCode::BR_0040,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
