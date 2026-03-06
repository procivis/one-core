use shared_types::{
    ClaimSchemaId, CredentialFormat, CredentialSchemaId, OrganisationId, RevocationMethodId,
};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential_schema::KeyStorageSecurity;

#[derive(thiserror::Error, Debug)]
pub enum CredentialSchemaServiceError {
    #[error("Credential schema `{0}` not found")]
    NotFound(CredentialSchemaId),
    #[error("Credential schema already exists")]
    AlreadyExists,

    #[error("Missing claim schemas")]
    MissingClaimSchemas,
    #[error("Missing parent claim schema for: {claim_schema_id}")]
    MissingParentClaimSchema { claim_schema_id: ClaimSchemaId },
    #[error("Forbidden claim name")]
    ForbiddenClaimName,
    #[error("Claim schema key exceeded max length (255)")]
    ClaimSchemaKeyTooLong,
    #[error("Credential schema: Duplicit claim schema")]
    DuplicitClaim,
    #[error("Credential schema: Missing nested claims for type '{0}'")]
    MissingNestedClaims(String),
    #[error("Credential schema: Nested claims should be empty for type '{0}'")]
    NestedClaimsShouldBeEmpty(String),
    #[error("Credential schema: Claim `{0}` name contains invalid character '/'")]
    ClaimSchemaSlashInKeyName(String),
    #[error("Credential schema: Claim `{claim_name}` data type {data_type} is unsupported")]
    ClaimSchemaUnsupportedDatatype {
        claim_name: String,
        data_type: String,
    },
    #[error("Invalid claim type (mdoc top level only objects allowed)")]
    InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed,
    #[error("Schema ID not allowed")]
    SchemaIdNotAllowed,
    #[error("Attribute combination not allowed")]
    AttributeCombinationNotAllowed,
    #[error("Layout attribute doesn't exists: `{0}`")]
    MissingLayoutAttribute(String),
    #[error("Layout properties are not supported")]
    LayoutPropertiesNotSupported,
    #[error("Revocation method not compatible with selected format")]
    RevocationMethodNotCompatibleWithSelectedFormat,
    #[error("Suspension not supported for revocation method")]
    SuspensionNotAvailableForSelectedRevocationMethod,
    #[error("Suspension not enabled for suspend-only revocation method")]
    SuspensionNotEnabledForSuspendOnlyRevocationMethod,
    #[error("Transaction code not supported")]
    TransactionCodeNotSupported,
    #[error("Invalid transaction code length")]
    InvalidTransactionCodeLength,
    #[error("Invalid transaction code description length")]
    InvalidTransactionCodeDescriptionLength,

    #[error("Key storage security level `{0}` not supported")]
    KeyStorageSecurityDisabled(KeyStorageSecurity),
    #[error("Cannot find `{0}` in revocation method provider")]
    MissingRevocationMethod(RevocationMethodId),
    #[error("Cannot find `{0}` formatter")]
    MissingFormat(CredentialFormat),
    #[error("Missing organisation: {0}")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for CredentialSchemaServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0006,
            Self::AlreadyExists => ErrorCode::BR_0007,
            Self::MissingClaimSchemas => ErrorCode::BR_0008,
            Self::MissingParentClaimSchema { .. } => ErrorCode::BR_0109,
            Self::ForbiddenClaimName => ErrorCode::BR_0145,
            Self::ClaimSchemaKeyTooLong => ErrorCode::BR_0126,
            Self::DuplicitClaim => ErrorCode::BR_0133,
            Self::SchemaIdNotAllowed => ErrorCode::BR_0139,
            Self::AttributeCombinationNotAllowed => ErrorCode::BR_0118,
            Self::KeyStorageSecurityDisabled(_) => ErrorCode::BR_0309,
            Self::TransactionCodeNotSupported => ErrorCode::BR_0337,
            Self::MissingLayoutAttribute(_) => ErrorCode::BR_0105,
            Self::LayoutPropertiesNotSupported => ErrorCode::BR_0131,
            Self::InvalidTransactionCodeLength => ErrorCode::BR_0338,
            Self::InvalidTransactionCodeDescriptionLength => ErrorCode::BR_0346,
            Self::MissingNestedClaims(_) => ErrorCode::BR_0106,
            Self::NestedClaimsShouldBeEmpty(_) => ErrorCode::BR_0107,
            Self::ClaimSchemaSlashInKeyName(_) => ErrorCode::BR_0108,
            Self::ClaimSchemaUnsupportedDatatype { .. } => ErrorCode::BR_0245,
            Self::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed => ErrorCode::BR_0117,
            Self::RevocationMethodNotCompatibleWithSelectedFormat => ErrorCode::BR_0110,
            Self::SuspensionNotEnabledForSuspendOnlyRevocationMethod => ErrorCode::BR_0191,
            Self::SuspensionNotAvailableForSelectedRevocationMethod => ErrorCode::BR_0162,
            Self::MissingRevocationMethod(_) => ErrorCode::BR_0044,
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::MissingFormat(_) => ErrorCode::BR_0038,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
