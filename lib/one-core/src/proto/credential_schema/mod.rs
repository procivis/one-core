use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

pub(crate) mod dto;
pub(crate) mod importer;
pub(crate) mod parser;
pub mod transaction_code;

#[cfg(test)]
mod test;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Credential schema already exists")]
    AlreadyExists,
    #[error("Revocation method not compatible with selected format")]
    RevocationMethodNotCompatibleWithSelectedFormat,
    #[error("Suspension not supported for revocation method")]
    SuspensionNotAvailableForSelectedRevocationMethod,
    #[error("Suspension not enabled for suspend-only revocation method")]
    SuspensionNotEnabledForSuspendOnlyRevocationMethod,
    #[error("Layout properties are not supported")]
    LayoutPropertiesNotSupported,
    #[error("Missing schema ID")]
    MissingSchemaId,
    #[error("Claim schema key exceeded max length (255)")]
    ClaimSchemaKeyTooLong,
    #[error("Invalid claim type (mdoc top level only objects allowed)")]
    InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed,
    #[error("Credential schema: Missing claims")]
    MissingClaims,
    #[error("Credential schema: Claim `{0}` name contains invalid character '/'")]
    ClaimSchemaSlashInKeyName(String),
    #[error("Forbidden claim name")]
    ForbiddenClaimName,
    #[error("Credential schema: Duplicit claim schema")]
    DuplicitClaim,
    #[error("Credential schema: Missing nested claims for type '{0}'")]
    MissingNestedClaims(String),
    #[error("Credential schema: Nested claims should be empty for type '{0}'")]
    NestedClaimsShouldBeEmpty(String),
    #[error("Credential schema: Claim `{claim_name}` data type {data_type} is unsupported")]
    ClaimSchemaUnsupportedDatatype {
        claim_name: String,
        data_type: String,
    },
    #[error("Attribute combination not allowed")]
    AttributeCombinationNotAllowed,
    #[error("Layout attribute doesn't exists: `{0}`")]
    MissingLayoutAttribute(String),

    #[expect(clippy::enum_variant_names)]
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::AlreadyExists => ErrorCode::BR_0007,
            Self::MissingClaims => ErrorCode::BR_0008,
            Self::RevocationMethodNotCompatibleWithSelectedFormat => ErrorCode::BR_0110,
            Self::SuspensionNotAvailableForSelectedRevocationMethod => ErrorCode::BR_0162,
            Self::SuspensionNotEnabledForSuspendOnlyRevocationMethod => ErrorCode::BR_0191,
            Self::LayoutPropertiesNotSupported => ErrorCode::BR_0131,
            Self::MissingSchemaId => ErrorCode::BR_0138,
            Self::ClaimSchemaKeyTooLong => ErrorCode::BR_0126,
            Self::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed => ErrorCode::BR_0117,
            Self::ForbiddenClaimName => ErrorCode::BR_0145,
            Self::DuplicitClaim => ErrorCode::BR_0133,
            Self::MissingNestedClaims(_) => ErrorCode::BR_0106,
            Self::NestedClaimsShouldBeEmpty(_) => ErrorCode::BR_0107,
            Self::ClaimSchemaSlashInKeyName(_) => ErrorCode::BR_0108,
            Self::ClaimSchemaUnsupportedDatatype { .. } => ErrorCode::BR_0245,
            Self::AttributeCombinationNotAllowed => ErrorCode::BR_0118,
            Self::MissingLayoutAttribute(_) => ErrorCode::BR_0105,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
