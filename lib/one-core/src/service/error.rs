use shared_types::{DidId, DidValue};
use strum_macros::IntoStaticStr;
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
    #[error("Mapping error: `{0}`")]
    MappingError(String),

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

    #[error("Credential revocation status list bitstring error `{0}`")]
    BitstringError(#[from] BitstringError),

    #[error("Missing signer for algorithm `{0}`")]
    MissingSigner(String),

    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),

    #[error("Missing transport protocol `{0}`")]
    MissingTransportProtocol(String),

    #[error(transparent)]
    MissingProvider(#[from] MissingProviderError),

    #[error("Key algorithm error `{0}`")]
    KeyAlgorithmError(String),

    #[error("Key storage error `{0}`")]
    KeyStorageError(anyhow::Error),

    #[error("Did method error `{0}`")]
    DidMethodError(#[from] DidMethodError),

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
    Repository(#[from] DataLayerError),

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

    #[error("Incapable DID method: {key_algorithm}")]
    DidMethodIncapableKeyAlgorithm { key_algorithm: String },

    #[error("Did value already exists: {0}")]
    DidValueAlreadyExists(DidValue),

    #[error("Credential schema already exists")]
    CredentialSchemaAlreadyExists,

    #[error("Key already exists")]
    KeyAlreadyExists,

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

    #[error("Missing interaction for access token: {interaction_id}")]
    MissingInteractionForAccessToken { interaction_id: Uuid },

    #[error("Missing credential index on revocation list: {credential_id} for DID: {did}")]
    MissingCredentialIndexOnRevocationList {
        credential_id: uuid::Uuid,
        did: DidId,
    },

    #[error("Some of the provided claim schema ids are missing")]
    MissingClaimSchemas,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid exchange type {value}: {source}")]
    InvalidExchangeType {
        value: String,
        source: anyhow::Error,
    },

    #[error("Invalid formatter: {0}")]
    InvalidFormatter(String),

    #[error("Invalid key algorithm: {0}")]
    InvalidKeyAlgorithm(String),

    #[error("Invalid key storage type: {0}")]
    InvalidKeyStorage(String),

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

    #[error("Invalid datatype `{datatype}` for value `{value}`: {source}")]
    InvalidDatatype {
        datatype: String,
        value: String,
        source: ConfigValidationError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum MissingProviderError {
    #[error("Cannot find `{0}` in formatter provider")]
    Formatter(String),

    #[error("Cannot find `{0}` in key storage provider")]
    KeyStorage(String),

    #[error("Cannot find `{0}` in did method provider")]
    DidMethod(String),

    #[error("Cannot find `{0}` in key algorithm provider")]
    KeyAlgorithm(String),

    #[error("Cannot find `{0}` in revocation method provider")]
    RevocationMethod(String),

    #[error("Cannot find revocation method provider for credential status type `{0}`")]
    RevocationMethodByCredentialStatusType(String),

    #[error("Cannot find `{0}` in transport protocol provider")]
    TransportProtocol(String),
}

impl MissingProviderError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            MissingProviderError::Formatter(_) => ErrorCode::BR_0038,
            MissingProviderError::KeyStorage(_) => ErrorCode::BR_0040,
            MissingProviderError::DidMethod(_) => ErrorCode::BR_0031,
            MissingProviderError::KeyAlgorithm(_) => ErrorCode::BR_0042,
            MissingProviderError::RevocationMethod(_) => ErrorCode::BR_0044,
            MissingProviderError::RevocationMethodByCredentialStatusType(_) => ErrorCode::BR_0045,
            MissingProviderError::TransportProtocol(_) => ErrorCode::BR_0046,
        }
    }
}

#[derive(Debug, Clone, Copy, IntoStaticStr)]
#[allow(non_camel_case_types)]
pub enum ErrorCode {
    #[strum(to_string = "Unmapped error code")]
    BR_0000,

    #[strum(to_string = "Credential not found")]
    BR_0001,

    #[strum(to_string = "Credential state invalid")]
    BR_0002,

    #[strum(to_string = "Credential: Missing claim")]
    BR_0003,

    #[strum(to_string = "Missing credentials for provided interaction")]
    BR_0004,

    #[strum(to_string = "Missing credential data for provided credential")]
    BR_0005,

    #[strum(to_string = "Credential schema not found")]
    BR_0006,

    #[strum(to_string = "Credential schema already exists")]
    BR_0007,

    #[strum(to_string = "Credential schema: Missing claims")]
    BR_0008,

    #[strum(to_string = "Missing credential schema")]
    BR_0009,

    #[strum(to_string = "Missing claim schema")]
    BR_0010,

    #[strum(to_string = "Missing claim schemas")]
    BR_0011,

    #[strum(to_string = "Proof not found")]
    BR_0012,

    #[strum(to_string = "Proof state invalid")]
    BR_0013,

    #[strum(to_string = "Proof schema not found")]
    BR_0014,

    #[strum(to_string = "Proof schema already exists")]
    BR_0015,

    #[strum(to_string = "Proof schema: missing claims ")]
    BR_0016,

    #[strum(to_string = "Proof schema: no required claim")]
    BR_0017,

    #[strum(to_string = "Proof schema: Duplicit claim schema")]
    BR_0018,

    #[strum(to_string = "The proof schema is deleted")]
    BR_0019,

    #[strum(to_string = "Missing proof schema")]
    BR_0020,

    #[strum(to_string = "The proof schema is deleted")]
    BR_0021,

    #[strum(to_string = "Organisation not found")]
    BR_0022,

    #[strum(to_string = "Organisation already exists")]
    BR_0023,

    #[strum(to_string = "DID not found")]
    BR_0024,

    #[strum(to_string = "Invalid DID type")]
    BR_0025,

    #[strum(to_string = "Invalid DID method")]
    BR_0026,

    #[strum(to_string = "DID deactivated")]
    BR_0027,

    #[strum(to_string = "DID value already exists")]
    BR_0028,

    #[strum(to_string = "DID cannot be deactivated ")]
    BR_0029,

    #[strum(to_string = "DID missing key")]
    BR_0030,

    #[strum(to_string = "Missing DID method")]
    BR_0031,

    #[strum(to_string = "Credential schema already exists")]
    BR_0032,

    #[strum(to_string = "Missing interaction for access token")]
    BR_0033,

    #[strum(to_string = "Revocation list not found")]
    BR_0034,

    #[strum(to_string = "Missing revocation list for provided DID")]
    BR_0035,

    #[strum(to_string = "Missing credential index on revocation list")]
    BR_0036,

    #[strum(to_string = "Key not found")]
    BR_0037,

    #[strum(to_string = "Missing formatter")]
    BR_0038,

    #[strum(to_string = "Generic key storage error")]
    BR_0039,

    #[strum(to_string = "Missing key storage")]
    BR_0040,

    #[strum(to_string = "Invalid key storage type")]
    BR_0041,

    #[strum(to_string = "Missing key algorithm")]
    BR_0042,

    #[strum(to_string = "Invalid key algorithm type")]
    BR_0043,

    #[strum(to_string = "Missing revocation method")]
    BR_0044,

    #[strum(to_string = "Missing revocation method for the provided credential status type")]
    BR_0045,

    #[strum(to_string = "Missing transport protocol")]
    BR_0046,

    #[strum(to_string = "Model mapping")]
    BR_0047,

    #[strum(to_string = "OpenID4VCI error")]
    BR_0048,

    #[strum(to_string = "Credential status list bitstring handling error")]
    BR_0049,

    #[strum(to_string = "Crypto provider error")]
    BR_0050,

    #[strum(to_string = "Configuration validation error")]
    BR_0051,

    #[strum(to_string = "Invalid exchange type")]
    BR_0052,

    #[strum(to_string = "Unsupported key type")]
    BR_0053,

    #[strum(to_string = "Database error")]
    BR_0054,

    #[strum(to_string = "Response mapping error")]
    BR_0055,

    #[strum(to_string = "Invalid formatter type")]
    BR_0056,

    #[strum(to_string = "Formatter provider error")]
    BR_0057,

    #[strum(to_string = "Crypto provider error")]
    BR_0058,

    #[strum(to_string = "Missing signer")]
    BR_0059,

    #[strum(to_string = "Missing signer algorithm")]
    BR_0060,

    #[strum(to_string = "Provided datatype is not valid or value doesn't match the expected type")]
    BR_0061,

    #[strum(to_string = "Transport protocol provider error")]
    BR_0062,

    #[strum(to_string = "Key algorithm provider error")]
    BR_0063,

    #[strum(to_string = "DID method provider error")]
    BR_0064,

    #[strum(to_string = "DID method is missing key algorithm capability")]
    BR_0065,

    #[strum(to_string = "Key already exists")]
    BR_0066,
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

impl ServiceError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ServiceError::EntityNotFound(error) => error.error_code(),
            ServiceError::BusinessLogic(error) => error.error_code(),
            ServiceError::Validation(error) => error.error_code(),
            ServiceError::Repository(error) => error.error_code(),
            ServiceError::MissingProvider(error) => error.error_code(),
            ServiceError::ResponseMapping(_) => ErrorCode::BR_0055,
            ServiceError::TransportProtocolError(_) => ErrorCode::BR_0062,
            ServiceError::CryptoError(_) => ErrorCode::BR_0050,
            ServiceError::FormatterError(_) => ErrorCode::BR_0058,
            ServiceError::KeyStorageError(_) => ErrorCode::BR_0039,
            ServiceError::MappingError(_) => ErrorCode::BR_0047,
            ServiceError::OpenID4VCError(_) => ErrorCode::BR_0048,
            ServiceError::ConfigValidationError(_) => ErrorCode::BR_0051,
            ServiceError::BitstringError(_) => ErrorCode::BR_0049,
            ServiceError::MissingSigner(_) => ErrorCode::BR_0060,
            ServiceError::MissingAlgorithm(_) => ErrorCode::BR_0061,
            ServiceError::MissingTransportProtocol(_) => ErrorCode::BR_0046,
            ServiceError::KeyAlgorithmError(_) => ErrorCode::BR_0063,
            ServiceError::DidMethodError(_) => ErrorCode::BR_0064,
            ServiceError::ValidationError(_) | ServiceError::Other(_) => ErrorCode::BR_0000,
        }
    }
}

impl EntityNotFoundError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            EntityNotFoundError::Credential(_) => ErrorCode::BR_0001,
            EntityNotFoundError::Did(_) => ErrorCode::BR_0024,
            EntityNotFoundError::RevocationList(_) => ErrorCode::BR_0034,
            EntityNotFoundError::ProofSchema(_) => ErrorCode::BR_0014,
            EntityNotFoundError::Proof(_) | EntityNotFoundError::ProofForInteraction(_) => {
                ErrorCode::BR_0012
            }
            EntityNotFoundError::Organisation(_) => ErrorCode::BR_0022,
            EntityNotFoundError::Key(_) => ErrorCode::BR_0037,
            EntityNotFoundError::CredentialSchema(_) => ErrorCode::BR_0006,
        }
    }
}

impl BusinessLogicError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            BusinessLogicError::OrganisationAlreadyExists => ErrorCode::BR_0023,
            BusinessLogicError::IncompatibleDidType { .. } => ErrorCode::BR_0025,
            BusinessLogicError::DidMethodIncapableKeyAlgorithm { .. } => ErrorCode::BR_0065,
            BusinessLogicError::InvalidDidMethod { .. } => ErrorCode::BR_0026,
            BusinessLogicError::DidIsDeactivated(_) => ErrorCode::BR_0027,
            BusinessLogicError::DidValueAlreadyExists(_) => ErrorCode::BR_0028,
            BusinessLogicError::CredentialSchemaAlreadyExists => ErrorCode::BR_0007,
            BusinessLogicError::InvalidCredentialState { .. } => ErrorCode::BR_0002,
            BusinessLogicError::ProofSchemaAlreadyExists => ErrorCode::BR_0015,
            BusinessLogicError::InvalidProofState { .. } => ErrorCode::BR_0013,
            BusinessLogicError::MissingCredentialsForInteraction { .. } => ErrorCode::BR_0004,
            BusinessLogicError::ProofSchemaDeleted { .. } => ErrorCode::BR_0019,
            BusinessLogicError::MissingCredentialData { .. } => ErrorCode::BR_0005,
            BusinessLogicError::MissingCredentialSchema => ErrorCode::BR_0009,
            BusinessLogicError::MissingClaimSchema { .. } => ErrorCode::BR_0010,
            BusinessLogicError::MissingRevocationListForDid { .. } => ErrorCode::BR_0035,
            BusinessLogicError::MissingProofSchema { .. } => ErrorCode::BR_0020,
            BusinessLogicError::MissingInteractionForAccessToken { .. } => ErrorCode::BR_0033,
            BusinessLogicError::MissingCredentialIndexOnRevocationList { .. } => ErrorCode::BR_0036,
            BusinessLogicError::MissingClaimSchemas => ErrorCode::BR_0011,
            BusinessLogicError::DidDeactivation(error) => error.error_code(),
            BusinessLogicError::KeyAlreadyExists => ErrorCode::BR_0066,
        }
    }
}

impl ValidationError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ValidationError::InvalidExchangeType { .. } => ErrorCode::BR_0052,
            ValidationError::UnsupportedKeyType { .. } => ErrorCode::BR_0053,
            ValidationError::DidMissingKey => ErrorCode::BR_0030,
            ValidationError::CredentialSchemaMissingClaims => ErrorCode::BR_0008,
            ValidationError::CredentialMissingClaim { .. } => ErrorCode::BR_0003,
            ValidationError::ProofSchemaMissingClaims => ErrorCode::BR_0016,
            ValidationError::ProofSchemaNoRequiredClaim => ErrorCode::BR_0017,
            ValidationError::ProofSchemaDuplicitClaim => ErrorCode::BR_0018,
            ValidationError::InvalidFormatter(_) => ErrorCode::BR_0056,
            ValidationError::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            ValidationError::InvalidKeyStorage(_) => ErrorCode::BR_0041,
            ValidationError::InvalidDatatype { .. } => ErrorCode::BR_0061,
        }
    }
}
