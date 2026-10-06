use std::string::FromUtf8Error;

use one_crypto::encryption::EncryptionError;
use shared_types::{CredentialFormat, CredentialSchemaId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;

#[derive(Debug, Error)]
pub enum IssuanceProtocolError {
    #[error("Issuance protocol failure: `{0}`")]
    Failed(String),
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Failed to autogenerate binding: `{0}`")]
    BindingAutogenerationFailure(String),
    #[error("Incorrect credential schema type")]
    IncorrectCredentialSchemaType,
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
    #[error("Issuance not allowed by trust ecosystem")]
    DisallowedCredentialConfiguration,
    #[error("Credential schema `{0}` not found")]
    MissingCredentialSchema(CredentialSchemaId),
    #[error("Interaction not allowed - untrusted")]
    Untrusted,
    #[error("Refresh not possible: refresh token missing or expired")]
    RefreshNotPossible,
    #[error("Credential refresh not supported")]
    RefreshNotSupported,
    #[error("Refresh not supported for already issued credential format `{0}`")]
    FormatRefreshNotSupported(CredentialFormat),
    #[error("Rejection not supported")]
    RejectionNotSupported,
    #[error("Requirements for key not supported")]
    KeyRequirementsNotSupported,
    #[error("Wallet instance required")]
    WalletInstanceRequired,

    #[error("JSON error: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error("Encryption error: `{0}`")]
    Encryption(#[from] EncryptionError),

    #[error(transparent)]
    OpenIDIssuanceError(#[from] OpenIDIssuanceError),

    #[error(transparent)]
    Nested(#[from] NestedError),

    #[error("Invalid trust information: `{0}`")]
    TrustInformationError(String),

    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),
}

impl ErrorCodeMixin for IssuanceProtocolError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::IncorrectCredentialSchemaType => ErrorCode::BR_0087,
            Self::InvalidRequest(_) => ErrorCode::BR_0085,
            Self::Untrusted => ErrorCode::BR_0433,
            Self::Failed(_)
            | Self::Json(_)
            | Self::OpenIDIssuanceError(_)
            | Self::Encryption(_) => ErrorCode::BR_0062,
            Self::DidMismatch
            | Self::KeyMismatch
            | Self::CertificateMismatch
            | Self::CredentialVerificationFailed(_) => ErrorCode::BR_0173,
            Self::BindingAutogenerationFailure(_) => ErrorCode::BR_0217,
            Self::KeyRequirementsNotSupported => ErrorCode::BR_0225,
            Self::WalletInstanceRequired => ErrorCode::BR_0081,
            Self::RejectionNotSupported => ErrorCode::BR_0237,
            Self::DisallowedCredentialConfiguration => ErrorCode::BR_0490,
            Self::Suspended | Self::RefreshTooSoon | Self::RefreshNotPossible => ErrorCode::BR_0238,
            Self::FromUtf8Error(_) | Self::TrustInformationError(_) => ErrorCode::BR_0047,
            Self::MissingCredentialSchema(_) => ErrorCode::BR_0006,
            Self::RefreshNotSupported => ErrorCode::BR_0452,
            Self::FormatRefreshNotSupported(_) => ErrorCode::BR_0483,
            Self::Nested(nested) => nested.error_code(),
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

impl ErrorCodeMixin for TxCodeError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::IncorrectCode => ErrorCode::BR_0169,
            Self::InvalidCodeUse => ErrorCode::BR_0170,
        }
    }
}

#[derive(Clone, Debug, Error)]
pub enum OpenID4VCIError {
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("invalid_client")]
    InvalidClient,
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
    #[error("invalid_encryption_parameters")]
    InvalidEncryptionParameters,

    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-11#name-errors
    #[error("use_attestation_challenge")]
    UseAttestationChallenge,
    #[error("use_fresh_attestation")]
    UseFreshAttestation,

    // https://www.rfc-editor.org/rfc/rfc9449.html#section-5
    #[error("invalid_dpop_proof")]
    InvalidDpopProof,

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
