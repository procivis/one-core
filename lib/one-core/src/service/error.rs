use shared_types::{DidId, DidValue};
use thiserror::Error;
use uuid::Uuid;

use crate::config::ConfigValidationError;
use crate::crypto::error::CryptoProviderError;
use crate::model::claim_schema::ClaimSchemaId;
use crate::model::credential::{CredentialId, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchemaId;
use crate::model::interaction::InteractionId;
use crate::model::key::KeyId;
use crate::model::organisation::OrganisationId;
use crate::model::proof::ProofId;
use crate::model::proof::ProofStateEnum;
use crate::model::proof_schema::ProofSchemaId;
use crate::model::revocation_list::RevocationListId;
use crate::service::oidc::dto::OpenID4VCIError;
use crate::{
    provider::credential_formatter::error::FormatterError,
    provider::did_method::DidMethodError,
    provider::transport_protocol::TransportProtocolError,
    repository::error::DataLayerError,
    util::{bitstring::BitstringError, oidc::FormatError},
};

use super::did::DidDeactivationError;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("General repository error `{0}`")]
    GeneralRuntimeError(String),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Not updated")]
    NotUpdated,
    #[error("Validation error: `{0}`")]
    ValidationError(String),
    #[error("OpenID4VCI validation error `{0}`")]
    OpenID4VCError(#[from] OpenID4VCIError),
    #[error("Config validation error `{0}`")]
    ConfigValidationError(#[from] ConfigValidationError),
    #[error("Transport protocol error `{0}`")]
    TransportProtocolError(#[from] TransportProtocolError),
    #[error("Formatter error `{0}`")]
    FormatterError(#[from] FormatterError),
    #[error("Bitstring error `{0}`")]
    BitstringError(#[from] BitstringError),
    #[error("Missing signer for algorithm `{0}`")]
    MissingSigner(String),
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Missing transport protocol `{0}`")]
    MissingTransportProtocol(String),
    #[error("Key algorithm error `{0}`")]
    KeyAlgorithmError(String),
    #[error("Did method error `{0}`")]
    DidMethodError(#[from] DidMethodError),
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("Other Repository error: `{0}`")]
    Other(String),

    #[error(transparent)]
    EntityNotFound(#[from] EntityNotFoundError),
    #[error("Not found")]
    NotFound,

    #[error(transparent)]
    BusinessLogic(#[from] BusinessLogicError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Repository(DataLayerError),
    #[error("Response mapping error: {0}")]
    ResponseMapping(String),
}

#[derive(Debug, thiserror::Error)]
pub enum EntityNotFoundError {
    #[error("Credential `{0}` not found")]
    Credential(CredentialId),

    #[error("Did `{0}` not found")]
    Did(DidId),

    #[error("Revocation list `{0}` not found")]
    RevocationList(RevocationListId),

    #[error("Proof schema `{0}` not found")]
    ProofSchema(ProofSchemaId),

    #[error("Proof `{0}` not found")]
    Proof(ProofId),

    #[error("Proof for interaction `{0}` not found")]
    ProofForInteraction(InteractionId),

    #[error("Organisation `{0}` not found")]
    Organisation(OrganisationId),

    #[error("Key `{0}` not found")]
    Key(KeyId),

    #[error("Credential schema `{0}` not found")]
    CredentialSchema(CredentialSchemaId),
}

#[derive(Debug, thiserror::Error)]
pub enum BusinessLogicError {
    #[error("Organisation already exists")]
    OrganisationAlreadyExists,

    #[error("Incompatible DID type, reason: {reason}")]
    IncompatibleDidType { reason: String },

    #[error("DID {0} is deactivated")]
    DidIsDeactivated(DidId),

    #[error("Invalid DID method: {method}")]
    InvalidDidMethod { method: String },

    #[error("Did value already exists: {0}")]
    DidValueAlreadyExists(DidValue),

    #[error("Credential schema already exists")]
    CredentialSchemaAlreadyExists,

    #[error("Invalid Credential state: {state}")]
    InvalidCredentialState { state: CredentialStateEnum },

    #[error("Proof schema already exists")]
    ProofSchemaAlreadyExists,

    #[error("Invalid Proof state: {state}")]
    InvalidProofState { state: ProofStateEnum },

    #[error(transparent)]
    DidDeactivation(#[from] DidDeactivationError),

    #[error("Missing credentials for interaction: {interaction_id}")]
    MissingCredentialsForInteraction { interaction_id: Uuid },

    #[error("Missing revocation list for did: {did_id}")]
    MissingRevocationListForDid { did_id: DidId },

    #[error("Proof schema {proof_schema_id} is deleted")]
    ProofSchemaDeleted { proof_schema_id: Uuid },

    #[error("Missing credentials for credential: {credential_id}")]
    MissingCredentialData { credential_id: Uuid },

    #[error("Missing credential schema")]
    MissingCredentialSchema,

    #[error("Missing claim schema: {claim_schema_id}")]
    MissingClaimSchema { claim_schema_id: Uuid },

    #[error("Missing proof schema: {proof_schema_id}")]
    MissingProofSchema { proof_schema_id: Uuid },

    #[error("Missing formatter {formatter}")]
    MissingFormatter { formatter: String },

    #[error("Missing interaction for access token: {interaction_id}")]
    MissingInteractionForAccessToken { interaction_id: Uuid },
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid exchange type {value}: {source}")]
    InvalidExchangeType {
        value: String,
        source: anyhow::Error,
    },

    #[error("Invalid formatter: {formatter}")]
    InvalidFormatter { formatter: String },

    #[error("Unsupported key type: {key_type}")]
    UnsupportedKeyType { key_type: String },

    #[error("DID: Missing key")]
    DidMissingKey,

    #[error("Credential schema: Missing claims")]
    CredentialSchemaMissingClaims,

    #[error("Credential: Missing claim, schema-id: {claim_schema_id}")]
    CredentialMissingClaim { claim_schema_id: ClaimSchemaId },

    #[error("Proof schema: Missing claims")]
    ProofSchemaMissingClaims,
    #[error("Proof schema: No required claim")]
    ProofSchemaNoRequiredClaim,
    #[error("Proof schema: Duplicit claim schema")]
    ProofSchemaDuplicitClaim,
}

#[derive(Debug)]
pub enum ErrorCode {
    OrganisationAlreadyExists,

    DidNotFound,
    DidInvalidType,
    DidInvalidMethod,
    DidDeactivated,
    DidValueAlreadyExists,
    DidCannotDeactivate,
    DidMissingKey,

    CredentialSchemaAlreadyExists,
    CredentialSchemaMissingClaims,

    Credential001,
    CredentialInvalidState,
    CredentialMissingClaim,

    ProofSchemaAlreadyExists,
    ProofSchemaMissingClaims,
    ProofSchemaNoRequiredClaim,
    ProofSchemaDuplicitClaim,

    ProofInvalidState,

    InvalidExchangeType,
    UnsupportedKeyType,

    Database,
    ResponseMapping,

    MissingFormatter,
    InvalidFormatter,
    MissingCredentialsForInteraction,
    ProofSchemaDeleted,
    MissingCredentialData,
    MissingCredentialSchema,
    MissingClaimSchema,
    MissingRevocationListForDid,
    RevocationListNotFound,
    MissingProofSchema,
    ProofSchemaNotFound,
    ProofNotFound,
    OrganisationNotFound,
    KeyNotFound,
    CredentialSchemaNotFound,
    MissingInteractionForAccessToken,

    Unmapped,
}

impl From<FormatError> for ServiceError {
    fn from(value: FormatError) -> Self {
        match value {
            FormatError::MappingError(value) => ServiceError::MappingError(value),
        }
    }
}

impl From<uuid::Error> for ServiceError {
    fn from(value: uuid::Error) -> Self {
        ServiceError::MappingError(value.to_string())
    }
}

impl ErrorCode {
    pub const fn msg(&self) -> &'static str {
        match self {
            ErrorCode::OrganisationAlreadyExists => "Organisation already exists",

            ErrorCode::DidNotFound => "DID not found",
            ErrorCode::DidInvalidType => "Invalid DID type",
            ErrorCode::DidInvalidMethod => "Invalid DID method",
            ErrorCode::DidDeactivated => "DID deactivated",
            ErrorCode::DidValueAlreadyExists => "DID value already exists",
            ErrorCode::DidCannotDeactivate => "DID cannot be deactivated",
            ErrorCode::DidMissingKey => "DID missing key",

            ErrorCode::CredentialSchemaAlreadyExists => "Credential schema already exists",
            ErrorCode::CredentialSchemaMissingClaims => "Credential schema: Missing claims",

            ErrorCode::Credential001 => "Credential not found",
            ErrorCode::CredentialInvalidState => "Credential state invalid",
            ErrorCode::CredentialMissingClaim => "Credential: Missing claim",

            ErrorCode::ProofSchemaAlreadyExists => "Proof schema already exists",
            ErrorCode::ProofSchemaMissingClaims => "Proof schema: Missing claims",
            ErrorCode::ProofSchemaNoRequiredClaim => "Proof schema: No required claim",
            ErrorCode::ProofSchemaDuplicitClaim => "Proof schema: Duplicit claim schema",

            ErrorCode::ProofInvalidState => "Proof state invalid",

            ErrorCode::InvalidExchangeType => "Invalid exchange type",
            ErrorCode::UnsupportedKeyType => "Unsupported key type",

            ErrorCode::Database => "Database error",

            ErrorCode::ResponseMapping => "Response mapping error",

            ErrorCode::Unmapped => "Unmapped error code",

            ErrorCode::MissingFormatter => "Missing formatter",
            ErrorCode::InvalidFormatter => "Invalid formatter",
            ErrorCode::MissingCredentialsForInteraction => {
                "Missing credentials for provided interaction"
            }
            ErrorCode::ProofSchemaDeleted => "The proof schema is deleted",
            ErrorCode::MissingCredentialData => "Missing credential data for provided credential",
            ErrorCode::MissingCredentialSchema => "Missing credential schema",
            ErrorCode::MissingClaimSchema => "Missing claim schema",
            ErrorCode::MissingRevocationListForDid => "Missing revocation list for provided DID",
            ErrorCode::RevocationListNotFound => "Revocation list not found",
            ErrorCode::MissingProofSchema => "Missing proof schema",
            ErrorCode::ProofSchemaNotFound => "Proof schema not found",
            ErrorCode::ProofNotFound => "Proof not found",
            ErrorCode::OrganisationNotFound => "Organisation not found",
            ErrorCode::KeyNotFound => "Key not found",
            ErrorCode::CredentialSchemaNotFound => "Credential schema not found",
            ErrorCode::MissingInteractionForAccessToken => "Missing interaction for access token",
        }
    }
}

impl ServiceError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ServiceError::EntityNotFound(error) => error.error_code(),
            ServiceError::BusinessLogic(error) => error.error_code(),
            ServiceError::Validation(error) => error.error_code(),
            ServiceError::ResponseMapping(_) => ErrorCode::ResponseMapping,
            ServiceError::Repository(error) => error.error_code(),

            ServiceError::GeneralRuntimeError(_)
            | ServiceError::MappingError(_)
            | ServiceError::OpenID4VCError(_)
            | ServiceError::NotFound
            | ServiceError::NotUpdated
            | ServiceError::ValidationError(_)
            | ServiceError::ConfigValidationError(_)
            | ServiceError::TransportProtocolError(_)
            | ServiceError::FormatterError(_)
            | ServiceError::BitstringError(_)
            | ServiceError::MissingSigner(_)
            | ServiceError::MissingAlgorithm(_)
            | ServiceError::MissingTransportProtocol(_)
            | ServiceError::KeyAlgorithmError(_)
            | ServiceError::DidMethodError(_)
            | ServiceError::CryptoError(_)
            | ServiceError::Other(_) => ErrorCode::Unmapped,
        }
    }
}

impl EntityNotFoundError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            EntityNotFoundError::Credential(_) => ErrorCode::Credential001,
            EntityNotFoundError::Did(_) => ErrorCode::DidNotFound,
            EntityNotFoundError::RevocationList(_) => ErrorCode::RevocationListNotFound,
            EntityNotFoundError::ProofSchema(_) => ErrorCode::ProofSchemaNotFound,
            EntityNotFoundError::Proof(_) | EntityNotFoundError::ProofForInteraction(_) => {
                ErrorCode::ProofNotFound
            }
            EntityNotFoundError::Organisation(_) => ErrorCode::OrganisationNotFound,
            EntityNotFoundError::Key(_) => ErrorCode::KeyNotFound,
            EntityNotFoundError::CredentialSchema(_) => ErrorCode::CredentialSchemaNotFound,
        }
    }
}

impl BusinessLogicError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            BusinessLogicError::OrganisationAlreadyExists => ErrorCode::OrganisationAlreadyExists,
            BusinessLogicError::IncompatibleDidType { .. } => ErrorCode::DidInvalidType,
            BusinessLogicError::InvalidDidMethod { .. } => ErrorCode::DidInvalidMethod,
            BusinessLogicError::DidIsDeactivated(_) => ErrorCode::DidDeactivated,
            BusinessLogicError::DidValueAlreadyExists(_) => ErrorCode::DidValueAlreadyExists,
            BusinessLogicError::CredentialSchemaAlreadyExists => {
                ErrorCode::CredentialSchemaAlreadyExists
            }
            BusinessLogicError::InvalidCredentialState { .. } => ErrorCode::CredentialInvalidState,
            BusinessLogicError::ProofSchemaAlreadyExists => ErrorCode::ProofSchemaAlreadyExists,
            BusinessLogicError::InvalidProofState { .. } => ErrorCode::ProofInvalidState,
            BusinessLogicError::DidDeactivation(error) => error.error_code(),
            BusinessLogicError::MissingCredentialsForInteraction { .. } => {
                ErrorCode::MissingCredentialsForInteraction
            }
            BusinessLogicError::ProofSchemaDeleted { .. } => ErrorCode::ProofSchemaDeleted,
            BusinessLogicError::MissingCredentialData { .. } => ErrorCode::MissingCredentialData,
            BusinessLogicError::MissingCredentialSchema => ErrorCode::MissingCredentialSchema,
            BusinessLogicError::MissingClaimSchema { .. } => ErrorCode::MissingClaimSchema,
            BusinessLogicError::MissingRevocationListForDid { .. } => {
                ErrorCode::MissingRevocationListForDid
            }
            BusinessLogicError::MissingProofSchema { .. } => ErrorCode::MissingProofSchema,
            BusinessLogicError::MissingFormatter { .. } => ErrorCode::MissingFormatter,
            BusinessLogicError::MissingInteractionForAccessToken { .. } => {
                ErrorCode::MissingInteractionForAccessToken
            }
        }
    }
}

impl ValidationError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ValidationError::InvalidExchangeType { .. } => ErrorCode::InvalidExchangeType,
            ValidationError::UnsupportedKeyType { .. } => ErrorCode::UnsupportedKeyType,
            ValidationError::DidMissingKey => ErrorCode::DidMissingKey,
            ValidationError::CredentialSchemaMissingClaims => {
                ErrorCode::CredentialSchemaMissingClaims
            }
            ValidationError::CredentialMissingClaim { .. } => ErrorCode::CredentialMissingClaim,
            ValidationError::ProofSchemaMissingClaims => ErrorCode::ProofSchemaMissingClaims,
            ValidationError::ProofSchemaNoRequiredClaim => ErrorCode::ProofSchemaNoRequiredClaim,
            ValidationError::ProofSchemaDuplicitClaim => ErrorCode::ProofSchemaDuplicitClaim,
            ValidationError::InvalidFormatter { .. } => ErrorCode::InvalidFormatter,
        }
    }
}

// Remove this once we map all NotFound and NotUpdated errors
impl From<DataLayerError> for ServiceError {
    fn from(value: DataLayerError) -> Self {
        match value {
            DataLayerError::RecordNotFound => ServiceError::NotFound,
            DataLayerError::RecordNotUpdated => ServiceError::NotUpdated,
            _ => Self::Repository(value),
        }
    }
}
