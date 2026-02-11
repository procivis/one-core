use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::credential::CredentialStateEnum;

#[derive(Debug, Error)]
pub enum IssuanceProtocolError {
    #[error("Issuance protocol failure: `{0}`")]
    Failed(String),
    #[error("Issuance protocol disabled: `{0}`")]
    Disabled(String),
    #[error("Transport error: `{0}`")]
    Transport(anyhow::Error),
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Base url is unknown")]
    MissingBaseUrl,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Failed to autogenerate binding: `{0}`")]
    BindingAutogenerationFailure(String),
    #[error("Incorrect credential schema type")]
    IncorrectCredentialSchemaType,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error(transparent)]
    StorageAccessError(anyhow::Error),
    #[error(transparent)]
    TxCode(TxCodeError),
    #[error("Credential offer issuer did does not match credential issuer did")]
    DidMismatch,
    #[error("Credential offer issuer certificate does not match credential issuer certificate")]
    CertificateMismatch,
    #[error("Credential offer issuer key does not match credential issuer certificate")]
    KeyMismatch,
    #[error("Credential signature verification failed: `{0}`")]
    CredentialVerificationFailed(anyhow::Error),
    #[error("Credential is suspended")]
    Suspended,
    #[error("Credential refresh is not yet possible")]
    RefreshTooSoon,
}

impl ErrorCodeMixin for IssuanceProtocolError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Failed(_) => ErrorCode::BR_0062,
            Self::IncorrectCredentialSchemaType => ErrorCode::BR_0087,
            Self::Transport(_) => ErrorCode::BR_0086,
            Self::JsonError(_) => ErrorCode::BR_0062,
            Self::OperationNotSupported => ErrorCode::BR_0062,
            Self::MissingBaseUrl => ErrorCode::BR_0062,
            Self::InvalidRequest(_) => ErrorCode::BR_0085,
            Self::Disabled(_) => ErrorCode::BR_0085,
            Self::Other(_) => ErrorCode::BR_0062,
            Self::StorageAccessError(_) => ErrorCode::BR_0062,
            Self::TxCode(tx_code_error) => match tx_code_error {
                TxCodeError::IncorrectCode => ErrorCode::BR_0169,
                TxCodeError::InvalidCodeUse => ErrorCode::BR_0170,
            },
            Self::DidMismatch
            | Self::KeyMismatch
            | Self::CertificateMismatch
            | Self::CredentialVerificationFailed(_) => ErrorCode::BR_0173,
            Self::BindingAutogenerationFailure(_) => ErrorCode::BR_0217,
            Self::Suspended | Self::RefreshTooSoon => ErrorCode::BR_0238,
        }
    }
}

#[derive(Debug, Error)]
pub enum TxCodeError {
    #[error("Incorrect tx_code")]
    IncorrectCode,
    #[error("Invalid use of tx_code")]
    InvalidCodeUse,
}

#[derive(Clone, Debug, Error)]
pub enum OpenID4VCIError {
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("invalid_token")]
    InvalidToken,
    #[error("invalid_nonce")]
    InvalidNonce,
    #[error("invalid_or_missing_proof")]
    InvalidOrMissingProof,
    #[error("unsupported_credential_format")]
    UnsupportedCredentialFormat,
    #[error("unsupported_credential_type")]
    UnsupportedCredentialType,
    #[error("credential_request_denied")]
    CredentialRequestDenied,
    #[error("invalid_notification_id")]
    InvalidNotificationId,
    #[error("invalid_notification_request")]
    InvalidNotificationRequest,
    #[error("oidc runtime error: `{0}`")]
    RuntimeError(String),
}

#[derive(Debug, Error)]
pub enum OpenIDIssuanceError {
    #[error("Invalid credential state: `{state}`")]
    InvalidCredentialState { state: CredentialStateEnum },

    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("OpenID4VCI error: `{0}`")]
    OpenID4VCI(#[from] OpenID4VCIError),
}
