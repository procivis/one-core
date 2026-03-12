use shared_types::{CredentialId, CredentialSchemaId, InteractionId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};

#[derive(thiserror::Error, Debug)]
pub enum OID4VCIFinal1_0ServiceError {
    #[error("Missing interaction for access token: {interaction_id}")]
    MissingInteractionForAccessToken { interaction_id: InteractionId },
    #[error("Missing credentials for interaction: {interaction_id}")]
    MissingCredentialsForInteraction { interaction_id: InteractionId },
    #[error("Credential schema `{0}` not found")]
    MissingCredentialSchema(CredentialSchemaId),
    #[error("Credential `{0}` not found")]
    MissingCredential(CredentialId),
    #[error("Invalid credential state: `{0}`")]
    InvalidCredentialState(CredentialStateEnum),

    #[error("Validation error: `{0}`")]
    ValidationError(String),
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("OpenID4VCI validation error `{0}`")]
    OpenID4VCIError(#[from] OpenID4VCIError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for OID4VCIFinal1_0ServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingInteractionForAccessToken { .. } => ErrorCode::BR_0033,
            Self::MissingCredentialsForInteraction { .. } => ErrorCode::BR_0004,
            Self::MissingCredential(_) => ErrorCode::BR_0001,
            Self::InvalidCredentialState(_) => ErrorCode::BR_0002,
            Self::MissingCredentialSchema(_) => ErrorCode::BR_0006,
            Self::ValidationError(_) => ErrorCode::BR_0323,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::OpenID4VCIError(_) => ErrorCode::BR_0048,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

impl From<OpenIDIssuanceError> for OID4VCIFinal1_0ServiceError {
    fn from(value: OpenIDIssuanceError) -> Self {
        match value {
            OpenIDIssuanceError::InvalidCredentialState { state } => {
                Self::InvalidCredentialState(state)
            }
            OpenIDIssuanceError::ValidationError(err) => Self::ValidationError(err),
            OpenIDIssuanceError::OpenID4VCI(err) => Self::OpenID4VCIError(err),
        }
    }
}
