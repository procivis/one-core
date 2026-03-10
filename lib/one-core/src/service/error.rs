use one_crypto::CryptoProviderError;
use shared_types::{
    CredentialId, CredentialSchemaId, DidId, DidValue, HolderWalletUnitId, IdentifierId,
    InteractionId, OrganisationId, ProofId, RevocationListEntryId, RevocationMethodId, TaskId,
    TrustAnchorId, TrustEntityId, TrustEntityKey,
};
use thiserror::Error;

use crate::config::core_config::{FormatType, VerificationProtocolType};
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;
use crate::model::credential_schema::KeyStorageSecurity;
use crate::model::proof::ProofStateEnum;
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};
use crate::provider::trust_management::error::TrustManagementError;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("OpenID4VC validation error `{0}`")]
    OpenID4VCError(#[from] OpenID4VCError),

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

    #[error("Trust management error `{0}`")]
    TrustManagementError(#[from] TrustManagementError),

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

    #[error("Holder wallet unit `{0}` not found")]
    HolderWalletUnit(HolderWalletUnitId),
}

#[derive(Debug, thiserror::Error)]
pub enum BusinessLogicError {
    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),

    #[error("Organisation not specified")]
    OrganisationNotSpecified,

    #[error("Incompatible DID type, reason: {reason}")]
    IncompatibleDidType { reason: String },

    #[error("Incompatible identifier type, reason: {reason}")]
    IncompatibleIdentifierType { reason: String },

    #[error("Invalid DID method: {method}")]
    InvalidDidMethod { method: String },

    #[error("Key already exists")]
    KeyAlreadyExists,

    #[error("Invalid Credential state: {state}")]
    InvalidCredentialState { state: CredentialStateEnum },

    #[error("Invalid Proof state: {state}")]
    InvalidProofState { state: ProofStateEnum },

    #[error("Cannot retract proof with exchange type: {exchange_type}")]
    InvalidProofExchangeForRetraction {
        exchange_type: VerificationProtocolType,
    },

    #[error("Missing credentials for interaction: {interaction_id}")]
    MissingCredentialsForInteraction { interaction_id: InteractionId },

    #[error("Missing interaction for access token: {interaction_id}")]
    MissingInteractionForAccessToken { interaction_id: InteractionId },

    #[error("Some of the provided claim schema ids are missing")]
    MissingClaimSchemas,

    #[error("General input validation error")]
    GeneralInputValidationError,

    #[error("Missing proof for interaction `{0}`")]
    MissingProofForInteraction(InteractionId),

    #[error("Wallet storage type requirement cannot be fulfilled")]
    UnfulfilledWalletStorageType,

    #[error("Credential state is Revoked or Suspended and cannot be shared")]
    CredentialIsRevokedOrSuspended,

    #[error("Incompatible proof verification identifier")]
    IncompatibleProofVerificationIdentifier,

    #[error("Unsupported key type for CSR")]
    UnsupportedKeyTypeForCSR,

    #[error("Trust anchor name already in use")]
    TrustAnchorNameTaken,

    #[error("Trust anchor type not found")]
    UnknownTrustAnchorType,

    #[error("Trust anchor must be publish")]
    TrustAnchorMustBePublish,

    #[error("Trust anchor must be client")]
    TrustAnchorMustBeClient,

    #[error("Trust anchor invalid request: {reason}")]
    TrustAnchorInvalidCreateRequest { reason: String },

    #[error("trustAnchorId and entityId are already present")]
    TrustEntityAlreadyPresent,

    #[error("Trust anchor type is not SIMPLE_TRUST_LIST")]
    TrustAnchorTypeIsNotSimpleTrustList,

    #[error("No trust entity found for the given did: {0}")]
    MissingTrustEntity(DidId),

    #[error("Multiple matching trust anchors")]
    MultipleMatchingTrustAnchors,

    #[error("Trust entity has duplicates")]
    TrustEntityHasDuplicates,

    #[error("Trust anchor is disabled")]
    TrustAnchorIsDisabled,

    #[error("Certificate `{certificate_id}` is not associated with identifier `{identifier_id}`")]
    IdentifierCertificateIdMismatch {
        identifier_id: String,
        certificate_id: String,
    },

    #[error("Certificate id not specified")]
    CertificateIdNotSpecified,

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

    #[error("Invalid key algorithm: {0}")]
    InvalidKeyAlgorithm(String),

    #[error("Forbidden")]
    Forbidden,

    #[error("Invalid update request")]
    InvalidUpdateRequest,

    #[error("Deserialization error: `{0}`")]
    DeserializationError(String),

    #[error("Exchange protocol operation disabled")]
    InvalidExchangeOperation,

    #[error("Invalid image data: `{0}`")]
    InvalidImage(String),

    #[error("Identifier type `{0}` is disabled")]
    IdentifierTypeDisabled(String),

    #[error("Trust entity type not specified")]
    TrustEntityTypeNotSpecified,

    #[error("Trust entity has ambiguous ids specified")]
    TrustEntityAmbiguousIds,

    #[error("Trust entity type does not match ids or content")]
    TrustEntityTypeInvalid,

    #[error("Trust entity subject key identifier does not match")]
    TrustEntitySubjectKeyIdentifierDoesNotMatch,

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
            Self::OpenID4VCError(_) | Self::OpenID4VCIError(_) | Self::OpenIDIssuanceError(_) => {
                ErrorCode::BR_0048
            }
            Self::ValidationError(_) => ErrorCode::BR_0323,
            Self::Other(_) => ErrorCode::BR_0000,
            Self::TrustManagementError(_) => ErrorCode::BR_0185,
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
            Self::HolderWalletUnit(_) => ErrorCode::BR_0296,
            Self::RevocationListEntry(_) => ErrorCode::BR_0000,
        }
    }
}

impl ErrorCodeMixin for BusinessLogicError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::IncompatibleDidType { .. } => ErrorCode::BR_0025,
            Self::IncompatibleIdentifierType { .. } => ErrorCode::BR_0025,
            Self::InvalidDidMethod { .. } => ErrorCode::BR_0026,
            Self::InvalidCredentialState { .. } => ErrorCode::BR_0002,
            Self::InvalidProofState { .. } => ErrorCode::BR_0013,
            Self::MissingCredentialsForInteraction { .. } => ErrorCode::BR_0004,
            Self::MissingInteractionForAccessToken { .. } => ErrorCode::BR_0033,
            Self::MissingClaimSchemas => ErrorCode::BR_0011,
            Self::KeyAlreadyExists => ErrorCode::BR_0066,
            Self::GeneralInputValidationError => ErrorCode::BR_0084,
            Self::MissingProofForInteraction(_) => ErrorCode::BR_0094,
            Self::UnfulfilledWalletStorageType => ErrorCode::BR_0097,
            Self::CredentialIsRevokedOrSuspended => ErrorCode::BR_0099,
            Self::UnsupportedKeyTypeForCSR => ErrorCode::BR_0128,
            Self::TrustAnchorNameTaken => ErrorCode::BR_0113,
            Self::UnknownTrustAnchorType => ErrorCode::BR_0114,
            Self::TrustAnchorMustBePublish => ErrorCode::BR_0123,
            Self::TrustAnchorMustBeClient => ErrorCode::BR_0188,
            Self::TrustAnchorInvalidCreateRequest { .. } => ErrorCode::BR_0177,
            Self::TrustEntityAlreadyPresent => ErrorCode::BR_0120,
            Self::TrustAnchorTypeIsNotSimpleTrustList => ErrorCode::BR_0122,
            Self::MultipleMatchingTrustAnchors => ErrorCode::BR_0179,
            Self::TrustEntityHasDuplicates => ErrorCode::BR_0180,
            Self::TrustAnchorIsDisabled => ErrorCode::BR_0187,
            Self::MissingTrustEntity(_) => ErrorCode::BR_0186,
            Self::InvalidProofExchangeForRetraction { .. } => ErrorCode::BR_0199,
            Self::IncompatibleProofVerificationIdentifier => ErrorCode::BR_0218,
            Self::IdentifierCertificateIdMismatch { .. } | Self::CertificateIdNotSpecified => {
                ErrorCode::BR_0242
            }
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
            Self::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            Self::TransportNotAllowedForExchange => ErrorCode::BR_0160,
            Self::TransportsCombinationNotAllowed => ErrorCode::BR_0159,
            Self::InvalidTransportType { .. } => ErrorCode::BR_0112,
            Self::Forbidden => ErrorCode::BR_0178,
            Self::InvalidUpdateRequest => ErrorCode::BR_0181,
            Self::DeserializationError(_) => ErrorCode::BR_0189,
            Self::InvalidExchangeOperation { .. } => ErrorCode::BR_0196,
            Self::InvalidImage(_) => ErrorCode::BR_0193,
            Self::IdentifierTypeDisabled(_) => ErrorCode::BR_0227,
            Self::TrustEntityAmbiguousIds => ErrorCode::BR_0228,
            Self::TrustEntityTypeNotSpecified => ErrorCode::BR_0229,
            Self::TrustEntityTypeInvalid => ErrorCode::BR_0230,
            Self::TrustEntitySubjectKeyIdentifierDoesNotMatch => ErrorCode::BR_0231,
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
