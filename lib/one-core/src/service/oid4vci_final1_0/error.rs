use std::string::FromUtf8Error;

use shared_types::{CredentialId, IdentifierId, InteractionId};
use standardized_types::openid4vci::KeyStorageSecurityLevel;

use crate::error::{ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt, NestedError};
use crate::model::credential::{CredentialStateEnum, CredentialType};
use crate::provider::ecosystem::error::{EcosystemError, WalletAttestationRejection};
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};
use crate::validator::ecosystem::EcosystemValidationError;

/// Errors surfaced to the wallet when validating wallet attestations (WIA / KA)
/// during the OpenID4VCI final-1.0 token and credential exchanges.
#[derive(thiserror::Error, Debug)]
pub enum WalletAttestationError {
    #[error("Wallet Instance Attestation is malformed: {0}")]
    WiaMalformed(String),
    #[error("Key Attestation is malformed: {0}")]
    KaMalformed(String),
    #[error("Wallet Instance Attestation and Key Attestation issuers do not match")]
    WiaKaIssuerMismatch,
    #[error("Key storage security level `{0:?}` is not attested by the key attestation")]
    KeyStorageSecurityLevelMismatch(KeyStorageSecurityLevel),
    #[error("Missing OAuth attestation challenge")]
    MissingChallenge { fresh_challenge: String },
    #[error("Invalid OAuth attestation challenge")]
    InvalidChallenge { fresh_challenge: String },
    #[error(transparent)]
    Rejected(WalletAttestationRejection),
}

impl ErrorCodeMixin for WalletAttestationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::WiaMalformed(_) => ErrorCode::BR_0495,
            Self::KaMalformed(_) => ErrorCode::BR_0497,
            Self::WiaKaIssuerMismatch => ErrorCode::BR_0498,
            Self::KeyStorageSecurityLevelMismatch(_) => ErrorCode::BR_0500,
            Self::InvalidChallenge { .. } | Self::MissingChallenge { .. } => ErrorCode::BR_0153,
            Self::Rejected(rejection) => rejection.error_code(),
        }
    }
}

impl WalletAttestationError {
    /// OAuth2 `error` value for the OpenID4VCI error response body.
    pub fn oauth_error(&self) -> OpenID4VCIError {
        match self {
            // The WIA is the OAuth client attestation at the token endpoint.
            Self::WiaMalformed(_)
            | Self::Rejected(WalletAttestationRejection::WalletInstanceAttestation(_)) => {
                OpenID4VCIError::InvalidClient
            }
            Self::InvalidChallenge { .. } | Self::MissingChallenge { .. } => {
                OpenID4VCIError::UseAttestationChallenge
            }
            // The key attestation is part of the holder proof at the credential endpoint.
            _ => OpenID4VCIError::InvalidOrMissingProof,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum OID4VCIFinal1_0ServiceError {
    #[error("Missing interaction for access token: {interaction_id}")]
    MissingInteractionForAccessToken { interaction_id: InteractionId },
    #[error("Missing credentials for interaction: {interaction_id}")]
    MissingCredentialsForInteraction { interaction_id: InteractionId },
    #[error("Credential {id} has type `{type}`, which is not supported by this operation")]
    UnsupportedCredentialType {
        id: CredentialId,
        r#type: CredentialType,
    },
    #[error("Invalid credential state: `{0}`")]
    InvalidCredentialState(CredentialStateEnum),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error("Validation error: `{0}`")]
    ValidationError(String),
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("OpenID4VCI validation error `{0}`")]
    OpenID4VCIError(#[from] OpenID4VCIError),

    #[error(transparent)]
    WalletAttestation(#[from] WalletAttestationError),

    #[error(transparent)]
    Nested(#[from] NestedError),

    #[error("Identifier missing Authentication capable key or certificate: {0}")]
    MissingAuthenticationCapableKey(IdentifierId),
}

impl ErrorCodeMixin for OID4VCIFinal1_0ServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingInteractionForAccessToken { .. } => ErrorCode::BR_0033,
            Self::MissingCredentialsForInteraction { .. } => ErrorCode::BR_0004,
            Self::InvalidCredentialState(_) => ErrorCode::BR_0002,
            Self::ValidationError(_) => ErrorCode::BR_0323,
            Self::FromUtf8Error(_) | Self::MappingError(_) => ErrorCode::BR_0047,
            Self::OpenID4VCIError(_) => ErrorCode::BR_0048,
            Self::WalletAttestation(e) => e.error_code(),
            Self::Nested(nested) => nested.error_code(),
            Self::MissingAuthenticationCapableKey(_) => ErrorCode::BR_0418,
            Self::UnsupportedCredentialType { .. } => ErrorCode::BR_0442,
        }
    }
}

impl OID4VCIFinal1_0ServiceError {
    pub(super) fn from_ecosystem_validation(error: EcosystemValidationError) -> Self {
        match error {
            EcosystemValidationError::Rejected(EcosystemError::WalletAttestation(rejection)) => {
                WalletAttestationError::Rejected(rejection).into()
            }
            error => error.error_while("validating ecosystem").into(),
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
