use one_crypto::CryptoProviderError;
use shared_types::{
    CredentialId, CredentialSchemaId, DidId, DidValue, IdentifierId, InteractionId, OrganisationId,
    ProofId, RevocationListEntryId, RevocationMethodId, TaskId, TrustAnchorId, TrustEntityId,
    TrustEntityKey,
};
use thiserror::Error;

use crate::config::core_config::FormatType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;
use crate::model::credential_schema::KeyStorageSecurity;
use crate::model::proof::ProofStateEnum;
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("OpenID4VCI validation error `{0}`")]
    OpenID4VCIError(#[from] OpenID4VCIError),

    #[error("OpenID4VCI issuance error `{0}`")]
    OpenIDIssuanceError(#[from] OpenIDIssuanceError),

    #[error(transparent)]
    MissingProvider(#[from] MissingProviderError),

    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),

    #[error("Other Repository error: `{0}`")]
    Other(String),

    #[error(transparent)]
    EntityNotFound(#[from] EntityNotFoundError),

    #[error(transparent)]
    BusinessLogic(#[from] BusinessLogicError),

    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

#[derive(Debug, thiserror::Error)]
pub enum EntityNotFoundError {
    #[error("Credential `{0}` not found")]
    Credential(CredentialId),

    #[error("Did `{0}` not found")]
    Did(DidId),

    #[error("Did value `{0}` not found")]
    DidValue(DidValue),

    #[error("Identifier `{0}` not found")]
    Identifier(IdentifierId),

    #[error("Identifier by did id `{0}` not found")]
    IdentifierByDidId(DidId),

    #[error("Revocation list entry `{0}` not found")]
    RevocationListEntry(RevocationListEntryId),

    #[error("Proof `{0}` not found")]
    Proof(ProofId),

    #[error("Organisation `{0}` not found")]
    Organisation(OrganisationId),

    #[error("Credential schema `{0}` not found")]
    CredentialSchema(CredentialSchemaId),

    #[error("Trust anchor `{0}` not found")]
    TrustAnchor(TrustAnchorId),

    #[error("Trust entity `{0}` not found")]
    TrustEntity(TrustEntityId),

    #[error("Trust entity by entity key `{0}` not found")]
    TrustEntityByEntityKey(TrustEntityKey),
}

#[derive(Debug, thiserror::Error)]
pub enum BusinessLogicError {
    #[error("Organisation not specified")]
    OrganisationNotSpecified,

    #[error("Invalid DID method: {method}")]
    InvalidDidMethod { method: String },

    #[error("Invalid Credential state: {state}")]
    InvalidCredentialState { state: CredentialStateEnum },

    #[error("Invalid Proof state: {state}")]
    InvalidProofState { state: ProofStateEnum },

    #[error("Missing credentials for interaction: {interaction_id}")]
    MissingCredentialsForInteraction { interaction_id: InteractionId },

    #[error("Missing interaction for access token: {interaction_id}")]
    MissingInteractionForAccessToken { interaction_id: InteractionId },

    #[error("Some of the provided claim schema ids are missing")]
    MissingClaimSchemas,

    #[error("General input validation error")]
    GeneralInputValidationError,

    #[error("Incompatible proof verification identifier")]
    IncompatibleProofVerificationIdentifier,

    #[error("Verification protocol does not support this API endpoint version")]
    IncompatiblePresentationEndpoint,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid exchange type {value}: {source}")]
    InvalidExchangeType {
        value: String,
        source: anyhow::Error,
    },

    #[error("Invalid transport type {value}: {source}")]
    InvalidTransportType {
        value: String,
        source: anyhow::Error,
    },

    #[error("Transport combination not allowed")]
    TransportsCombinationNotAllowed,

    #[error("No suitable transport found for exchange")]
    TransportNotAllowedForExchange,

    #[error("No default transport specified")]
    MissingDefaultTransport,

    #[error("Forbidden")]
    Forbidden,

    #[error("Deserialization error: `{0}`")]
    DeserializationError(String),

    #[error("Exchange protocol operation disabled")]
    InvalidExchangeOperation,

    #[error("Invalid image data: `{0}`")]
    InvalidImage(String),

    #[error("Identifier type `{0}` is disabled")]
    IdentifierTypeDisabled(String),

    #[error("Invalid wallet provider url: {0}")]
    InvalidWalletProviderUrl(String),

    #[error(
        "Key storage `{key_storage}` does not fulfill required security levels {required_security_levels:?}"
    )]
    UnfulfilledKeyStorageSecurityLevel {
        key_storage: String,
        required_security_levels: Vec<KeyStorageSecurity>,
    },

    #[error("Key storage security level `{0}` not supported")]
    KeyStorageSecurityDisabled(KeyStorageSecurity),

    #[error("Invalid transaction code length")]
    InvalidTransactionCodeLength,

    #[error("Notifications not allowed for protocol: `{protocol}`")]
    NotificationsNotAllowed { protocol: String },
}

#[derive(Debug, thiserror::Error)]
pub enum MissingProviderError {
    #[error("Cannot find `{0}` in formatter provider")]
    Formatter(String),

    #[error("Cannot find formatter with type `{0}` in formatter provider")]
    FormatterType(FormatType),

    #[error("Cannot find `{0}` in key storage provider")]
    KeyStorage(String),

    #[error("Cannot find `{0}` in did method provider")]
    DidMethod(String),

    #[error("Cannot find `{0}` in revocation method provider")]
    RevocationMethod(RevocationMethodId),

    #[error("Cannot find revocation method provider for credential status type `{0}`")]
    RevocationMethodByCredentialStatusType(String),

    #[error("Cannot find `{0}` in exchange protocol provider")]
    ExchangeProtocol(String),

    #[error("Cannot find task `{0}`")]
    Task(TaskId),

    #[error("Cannot find trust manager `{0}`")]
    TrustManager(String),

    #[error("Cannot find blob storage `{0}`")]
    BlobStorage(String),

    #[error("Cannot find signature provider `{0}`")]
    Signer(String),

    #[error("Cannot find verifier provider `{0}`")]
    Verifier(String),
}

impl From<uuid::Error> for ServiceError {
    fn from(value: uuid::Error) -> Self {
        Self::MappingError(value.to_string())
    }
}

impl ErrorCodeMixin for ServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::EntityNotFound(error) => error.error_code(),
            Self::BusinessLogic(error) => error.error_code(),
            Self::Validation(error) => error.error_code(),
            Self::MissingProvider(error) => error.error_code(),
            Self::CryptoError(_) => ErrorCode::BR_0050,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::OpenID4VCIError(_) | Self::OpenIDIssuanceError(_) => ErrorCode::BR_0048,
            Self::ValidationError(_) => ErrorCode::BR_0323,
            Self::Other(_) => ErrorCode::BR_0000,
            Self::Nested(error) => error.error_code(),
        }
    }
}

impl ErrorCodeMixin for EntityNotFoundError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Credential(_) => ErrorCode::BR_0001,
            Self::Did(_) | Self::DidValue(_) => ErrorCode::BR_0024,
            Self::Proof(_) => ErrorCode::BR_0012,
            Self::Organisation(_) => ErrorCode::BR_0022,
            Self::CredentialSchema(_) => ErrorCode::BR_0006,
            Self::TrustAnchor(_) => ErrorCode::BR_0115,
            Self::TrustEntity(_) | Self::TrustEntityByEntityKey(_) => ErrorCode::BR_0121,
            Self::Identifier(_) | Self::IdentifierByDidId(_) => ErrorCode::BR_0207,
            Self::RevocationListEntry(_) => ErrorCode::BR_0000,
        }
    }
}

impl ErrorCodeMixin for BusinessLogicError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidDidMethod { .. } => ErrorCode::BR_0026,
            Self::InvalidCredentialState { .. } => ErrorCode::BR_0002,
            Self::InvalidProofState { .. } => ErrorCode::BR_0013,
            Self::MissingCredentialsForInteraction { .. } => ErrorCode::BR_0004,
            Self::MissingInteractionForAccessToken { .. } => ErrorCode::BR_0033,
            Self::MissingClaimSchemas => ErrorCode::BR_0011,
            Self::GeneralInputValidationError => ErrorCode::BR_0084,
            Self::IncompatibleProofVerificationIdentifier => ErrorCode::BR_0218,
            Self::OrganisationNotSpecified => ErrorCode::BR_0290,
            Self::IncompatiblePresentationEndpoint => ErrorCode::BR_0292,
        }
    }
}

impl ErrorCodeMixin for ValidationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidExchangeType { .. } => ErrorCode::BR_0052,
            Self::MissingDefaultTransport => ErrorCode::BR_0142,
            Self::TransportNotAllowedForExchange => ErrorCode::BR_0160,
            Self::TransportsCombinationNotAllowed => ErrorCode::BR_0159,
            Self::InvalidTransportType { .. } => ErrorCode::BR_0112,
            Self::Forbidden => ErrorCode::BR_0178,
            Self::DeserializationError(_) => ErrorCode::BR_0189,
            Self::InvalidExchangeOperation { .. } => ErrorCode::BR_0196,
            Self::InvalidImage(_) => ErrorCode::BR_0193,
            Self::IdentifierTypeDisabled(_) => ErrorCode::BR_0227,
            Self::InvalidWalletProviderUrl(_) => ErrorCode::BR_0295,
            Self::KeyStorageSecurityDisabled(_) => ErrorCode::BR_0309,
            Self::UnfulfilledKeyStorageSecurityLevel { .. } => ErrorCode::BR_0310,
            Self::InvalidTransactionCodeLength => ErrorCode::BR_0338,
            Self::NotificationsNotAllowed { .. } => ErrorCode::BR_0372,
        }
    }
}

impl ErrorCodeMixin for MissingProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Formatter(_) | Self::FormatterType(_) => ErrorCode::BR_0038,
            Self::KeyStorage(_) => ErrorCode::BR_0040,
            Self::DidMethod(_) => ErrorCode::BR_0031,
            Self::RevocationMethod(_) => ErrorCode::BR_0044,
            Self::RevocationMethodByCredentialStatusType(_) => ErrorCode::BR_0045,
            Self::ExchangeProtocol(_) => ErrorCode::BR_0046,
            Self::Task(_) => ErrorCode::BR_0103,
            Self::TrustManager(_) => ErrorCode::BR_0132,
            Self::BlobStorage(_) => ErrorCode::BR_0252,
            Self::Signer(_) => ErrorCode::BR_0326,
            Self::Verifier(_) => ErrorCode::BR_0380,
        }
    }
}
