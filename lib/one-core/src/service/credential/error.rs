use shared_types::{ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, IdentifierId};

use crate::config::ConfigValidationError;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;
use crate::model::identifier::IdentifierType;

#[derive(thiserror::Error, Debug)]
pub enum CredentialServiceError {
    #[error("Credential `{0}` not found")]
    NotFound(CredentialId),
    #[error("Invalid Credential state: {0}")]
    InvalidState(CredentialStateEnum),

    #[error("No issuer specified")]
    NoIssuer,
    #[error("Invalid identifier type: `{0}`")]
    InvalidIdentifierType(IdentifierType),
    #[error("Identifier {0} is deactivated")]
    IdentifierIsDeactivated(IdentifierId),
    #[error("Invalid datatype `{datatype}` for value `{value}`: {source}")]
    InvalidDatatype {
        datatype: String,
        value: String,
        source: ConfigValidationError,
    },
    #[error("Incompatible issuance did method")]
    IncompatibleIssuanceDidMethod,
    #[error("Incompatible issuance identifier")]
    IncompatibleIssuanceIdentifier,
    #[error("Incompatible issuance exchange protocol")]
    IncompatibleIssuanceExchangeProtocol,
    #[error("Redirect uri disabled or scheme not allowed")]
    InvalidRedirectUri,
    #[error("Notifications not allowed for protocol: `{protocol}`")]
    NotificationsNotAllowed { protocol: String },
    #[error("Empty object not allowed")]
    EmptyObjectNotAllowed,
    #[error("Empty array value not allowed")]
    EmptyArrayValueNotAllowed,
    #[error("Empty value not allowed")]
    EmptyValueNotAllowed,

    #[error("Missing claim schema: {0}")]
    MissingClaimSchema(ClaimSchemaId),
    #[error("Identifier `{0}` not found")]
    MissingIdentifier(IdentifierId),
    #[error("Did `{0}` not found")]
    MissingDid(DidId),
    #[error("Credential schema `{0}` not found")]
    MissingCredentialSchema(CredentialSchemaId),
    #[error("Missing parent claim schema for: {claim_schema_id}")]
    MissingParentClaimSchema { claim_schema_id: ClaimSchemaId },

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for CredentialServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0001,
            Self::InvalidState(_) => ErrorCode::BR_0002,
            Self::MissingClaimSchema(_) => ErrorCode::BR_0003,
            Self::MissingIdentifier(_) => ErrorCode::BR_0207,
            Self::MissingDid(_) => ErrorCode::BR_0024,
            Self::MissingCredentialSchema(_) => ErrorCode::BR_0006,
            Self::MissingParentClaimSchema { .. } => ErrorCode::BR_0109,
            Self::NoIssuer | Self::InvalidIdentifierType(_) => ErrorCode::BR_0323,
            Self::IncompatibleIssuanceIdentifier => ErrorCode::BR_0218,
            Self::IdentifierIsDeactivated(_) => ErrorCode::BR_0027,
            Self::InvalidDatatype { .. } => ErrorCode::BR_0061,
            Self::InvalidRedirectUri => ErrorCode::BR_0192,
            Self::NotificationsNotAllowed { .. } => ErrorCode::BR_0372,
            Self::EmptyObjectNotAllowed => ErrorCode::BR_0194,
            Self::EmptyArrayValueNotAllowed => ErrorCode::BR_0195,
            Self::EmptyValueNotAllowed => ErrorCode::BR_0204,
            Self::IncompatibleIssuanceDidMethod => ErrorCode::BR_0127,
            Self::IncompatibleIssuanceExchangeProtocol => ErrorCode::BR_0111,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
