use one_providers::crypto::{CryptoProviderError, SignerError};
use one_providers::key_algorithm::error::{KeyAlgorithmError, KeyAlgorithmProviderError};
use shared_types::{
    ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, DidValue, HistoryId, KeyId,
    OrganisationId, ProofId, ProofSchemaId, TrustAnchorId, TrustEntityId,
};
use strum_macros::Display;
use thiserror::Error;
use uuid::Uuid;

use super::did::DidDeactivationError;
use super::proof_schema::ProofSchemaImportError;
use crate::config::ConfigValidationError;
use crate::model::credential::CredentialStateEnum;
use crate::model::interaction::InteractionId;
use crate::model::proof::ProofStateEnum;
use crate::model::revocation_list::RevocationListId;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::did_method::DidMethodError;
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::repository::error::DataLayerError;
use crate::service::oidc::dto::OpenID4VCIError;
use crate::util::bitstring::BitstringError;
use crate::util::oidc::FormatError;

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

    #[error("Exchange protocol error `{0}`")]
    ExchangeProtocolError(#[from] ExchangeProtocolError),

    #[error("Formatter error `{0}`")]
    FormatterError(#[from] FormatterError),

    #[error("Credential revocation status list bitstring error `{0}`")]
    BitstringError(#[from] BitstringError),

    #[error("Missing signer for algorithm `{0}`")]
    MissingSigner(String),

    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),

    #[error("Missing exchange protocol `{0}`")]
    MissingExchangeProtocol(String),

    #[error(transparent)]
    MissingProvider(#[from] MissingProviderError),

    #[error(transparent)]
    KeyAlgorithmError(#[from] KeyAlgorithmError),

    #[error(transparent)]
    KeyAlgorithmProviderError(#[from] KeyAlgorithmProviderError),

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

    #[error(transparent)]
    KeyStorage(#[from] KeyStorageError),

    #[error("Response mapping error: {0}")]
    ResponseMapping(String),

    #[error("Revocation error: {0}")]
    Revocation(String),
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

    #[error("Organisation `{0}` not found")]
    Organisation(OrganisationId),

    #[error("Key `{0}` not found")]
    Key(KeyId),

    #[error("Credential schema `{0}` not found")]
    CredentialSchema(CredentialSchemaId),

    #[error("Lvvc with credentialId `{0}` not found")]
    Lvvc(CredentialId),

    #[error("History entry `{0}` not found")]
    History(HistoryId),

    #[error("Trust anchor `{0}` not found")]
    TrustAnchor(TrustAnchorId),

    #[error("Trust entity `{0}` not found")]
    TrustEntity(TrustEntityId),
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
    ProofSchemaDeleted { proof_schema_id: ProofSchemaId },

    #[error("Missing credentials for credential: {credential_id}")]
    MissingCredentialData { credential_id: CredentialId },

    #[error("Missing credential schema")]
    MissingCredentialSchema,

    #[error("Missing claim schema: {claim_schema_id}")]
    MissingClaimSchema { claim_schema_id: ClaimSchemaId },

    #[error("Missing parent claim schema for: {claim_schema_id}")]
    MissingParentClaimSchema { claim_schema_id: ClaimSchemaId },

    #[error("Missing proof schema: {proof_schema_id}")]
    MissingProofSchema { proof_schema_id: ProofSchemaId },

    #[error("Missing interaction for access token: {interaction_id}")]
    MissingInteractionForAccessToken { interaction_id: Uuid },

    #[error("Missing credential index on revocation list: {credential_id} for DID: {did}")]
    MissingCredentialIndexOnRevocationList {
        credential_id: CredentialId,
        did: DidId,
    },

    #[error("Some of the provided claim schema ids are missing")]
    MissingClaimSchemas,

    #[error("General input validation error")]
    GeneralInputValidationError,

    #[error("Missing organisation: {0}")]
    MissingOrganisation(OrganisationId),

    #[error("Missing proof for interaction `{0}`")]
    MissingProofForInteraction(InteractionId),

    #[error(
        "StatusList2021 revocation method not supported for credential issuance and revocation"
    )]
    StatusList2021NotSupported,

    #[error("Credential already revoked")]
    CredentialAlreadyRevoked,

    #[error("Revocation method does not support state ({operation})")]
    OperationNotSupportedByRevocationMethod { operation: String },

    #[error("Wallet storage type requirement cannot be fulfilled")]
    UnfulfilledWalletStorageType,

    #[error("Credential state is Revoked or Suspended and cannot be shared")]
    CredentialIsRevokedOrSuspended,

    #[error("Revocation method not compatible with selected format")]
    RevocationMethodNotCompatibleWithSelectedFormat,

    #[error("Incompatible issuance did method")]
    IncompatibleIssuanceDidMethod,

    #[error("Incompatible issuance exchange protocol")]
    IncompatibleIssuanceExchangeProtocol,

    #[error("Incompatible proof exchange protocol")]
    IncompatibleProofExchangeProtocol,

    #[error("Invalid claim type (mdoc top level only objects allowed)")]
    InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed,

    #[error("Missing MDOC doctype")]
    MissingMdocDoctype,

    #[error("Schema ID not allowed")]
    SchemaIdNotAllowed,

    #[error("Claim schema key exceeded max length (255)")]
    ClaimSchemaKeyTooLong,

    #[error("Unsupported key type for CSR")]
    UnsupportedKeyTypeForCSR,

    #[error("Incorrect nested disclosure level")]
    IncorrectDisclosureLevel,

    #[error("Trust anchor name already in use")]
    TrustAnchorNameTaken,

    #[error("Trust anchor type not found")]
    UnknownTrustAnchorType,

    #[error("Trust anchor must be publish")]
    TrustAnchorMustBePublish,

    #[error("trustAnchorId and entityId are already present")]
    TrustEntityAlreadyPresent,

    #[error("Trust anchor type is not SIMPLE_TRUST_LIST")]
    TrustAnchorTypeIsNotSimpleTrustList,

    #[error("Error while importing proof request schema: {0}")]
    ProofSchemaImport(#[from] ProofSchemaImportError),
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid exchange type {value}: {source}")]
    InvalidExchangeType {
        value: String,
        source: anyhow::Error,
    },

    #[error("No default transport specified")]
    MissingDefaultTransport,

    #[error("Invalid formatter: {0}")]
    InvalidFormatter(String),

    #[error("Invalid key algorithm: {0}")]
    InvalidKeyAlgorithm(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("BBS not supported")]
    BBSNotSupported,

    #[error("Invalid key storage type: {0}")]
    InvalidKeyStorage(String),

    #[error("Unsupported key type: {key_type}")]
    UnsupportedKeyType { key_type: String },

    #[error("Unsupported key operation")]
    UnsupportedKeyOperation,

    #[error("DID: Invalid key number")]
    DidInvalidKeyNumber,

    #[error("Credential schema: Missing claims")]
    CredentialSchemaMissingClaims,

    #[error("Credential schema: Missing nested claims for type '{0}'")]
    CredentialSchemaMissingNestedClaims(String),

    #[error("Credential schema: Nested claims should be empty for type '{0}'")]
    CredentialSchemaNestedClaimsShouldBeEmpty(String),

    #[error("Credential schema: Claim `{0}` name contains invalid character '/'")]
    CredentialSchemaClaimSchemaSlashInKeyName(String),

    #[error("Credential schema: Duplicit claim schema")]
    CredentialSchemaDuplicitClaim,

    #[error("Credential: Missing claim, schema-id: {claim_schema_id}")]
    CredentialMissingClaim { claim_schema_id: ClaimSchemaId },

    #[error("Proof schema: Missing proof input schemas")]
    ProofSchemaMissingProofInputSchemas,

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

    #[error("Did not found")]
    DidNotFound,

    #[error("Key not found")]
    KeyNotFound,

    #[error("Layout attribute doesn't exists: `{0}`")]
    MissingLayoutAttribute(String),

    #[error("Attribute combination not allowed")]
    AttributeCombinationNotAllowed,

    #[error("Certificate requested for more than 457 days of validity")]
    CertificateRequestedForMoreThan457Days,

    #[error("Nested claims in arrays cannot be requested")]
    NestedClaimInArrayRequested,

    #[error("Validity constraint must be specified for LVVC revocation method")]
    ValidityConstraintMissingForLvvc,

    #[error("Schema id not allowed for format")]
    SchemaIdNotAllowedForFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum MissingProviderError {
    #[error("Cannot find `{0}` in formatter provider")]
    Formatter(String),

    #[error("Cannot find `{0}` in key storage provider")]
    KeyStorage(String),

    #[error("Cannot find `{0}` in did method provider")]
    DidMethod(String),

    #[error(transparent)]
    KeyAlgorithm(#[from] KeyAlgorithmError),

    #[error(transparent)]
    KeyAlgorithmProvider(#[from] KeyAlgorithmProviderError),

    #[error("Cannot find `{0}` in revocation method provider")]
    RevocationMethod(String),

    #[error("Cannot find revocation method provider for credential status type `{0}`")]
    RevocationMethodByCredentialStatusType(String),

    #[error("Cannot find `{0}` in exchange protocol provider")]
    ExchangeProtocol(String),

    #[error("Cannot find task `{0}`")]
    Task(String),

    #[error("Cannot find trust manager `{0}`")]
    TrustManager(String),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStorageError {
    #[error("Password decryption failure")]
    PasswordDecryptionFailure,

    #[error("Signer error: `{0}`")]
    SignerError(#[from] SignerError),
    #[error("Rcgen error: `{0}`")]
    RcgenError(#[from] rcgen::Error),
}

impl MissingProviderError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            MissingProviderError::Formatter(_) => ErrorCode::BR_0038,
            MissingProviderError::KeyStorage(_) => ErrorCode::BR_0040,
            MissingProviderError::DidMethod(_) => ErrorCode::BR_0031,
            MissingProviderError::KeyAlgorithm(_) => ErrorCode::BR_0042,
            MissingProviderError::KeyAlgorithmProvider(_) => ErrorCode::BR_0042,
            MissingProviderError::RevocationMethod(_) => ErrorCode::BR_0044,
            MissingProviderError::RevocationMethodByCredentialStatusType(_) => ErrorCode::BR_0045,
            MissingProviderError::ExchangeProtocol(_) => ErrorCode::BR_0046,
            MissingProviderError::Task(_) => ErrorCode::BR_0103,
            MissingProviderError::TrustManager(_) => ErrorCode::BR_0132,
        }
    }
}

#[derive(Debug, Clone, Copy, Display, PartialEq, Eq)]
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

    #[strum(to_string = "DID invalid key number")]
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

    #[strum(to_string = "Missing exchange protocol")]
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

    #[strum(to_string = "Exchange protocol provider error")]
    BR_0062,

    #[strum(to_string = "Key algorithm provider error")]
    BR_0063,

    #[strum(to_string = "DID method provider error")]
    BR_0064,

    #[strum(to_string = "DID method is missing key algorithm capability")]
    BR_0065,

    #[strum(to_string = "Key already exists")]
    BR_0066,

    #[strum(to_string = "General input validation error")]
    BR_0084,

    #[strum(to_string = "Invalid handle invitation received")]
    BR_0085,

    #[strum(to_string = "Cannot fetch credential offer or presentation definition")]
    BR_0086,

    #[strum(to_string = "Incorrect credential schema type")]
    BR_0087,

    #[strum(to_string = "Missing organisation")]
    BR_0088,

    #[strum(to_string = "Missing configuration entity")]
    BR_0089,

    #[strum(to_string = "JSON-LD: BBS key needed")]
    BR_0090,

    #[strum(to_string = "BBS key not supported")]
    BR_0091,

    #[strum(to_string = "Credential already revoked")]
    BR_0092,

    #[strum(to_string = "Missing proof for provided interaction")]
    BR_0094,

    #[strum(to_string = "StatusList2021 not supported for credential issuance and revocation")]
    BR_0095,

    #[strum(to_string = "Invalid key")]
    BR_0096,

    #[strum(to_string = "Requested wallet storage type cannot be fulfilled")]
    BR_0097,

    #[strum(to_string = "Revocation method does not support state (REVOKE, SUSPEND)")]
    BR_0098,

    #[strum(to_string = "Credential state is Revoked or Suspended and cannot be shared")]
    BR_0099,

    #[strum(to_string = "History event not found")]
    BR_0100,

    #[strum(to_string = "Revocation error")]
    BR_0101,

    #[strum(to_string = "Missing task")]
    BR_0103,

    #[strum(to_string = "Missing proof input schemas")]
    BR_0104,

    #[strum(to_string = "Primary/Secondary attribute does not exists")]
    BR_0105,

    #[strum(to_string = "Missing nested claims")]
    BR_0106,

    #[strum(to_string = "Nested claims should be empty")]
    BR_0107,

    #[strum(to_string = "Slash in claim schema key name")]
    BR_0108,

    #[strum(to_string = "Missing parent claim schema")]
    BR_0109,

    #[strum(to_string = "Revocation method not compatible")]
    BR_0110,

    #[strum(to_string = "Incompatible issuance exchange protocol")]
    BR_0111,

    #[strum(to_string = "Incompatible proof exchange protocol")]
    BR_0112,

    #[strum(to_string = "Trust anchor name already in use")]
    BR_0113,

    #[strum(to_string = "Trust anchor type not found")]
    BR_0114,

    #[strum(to_string = "Trust anchor not found")]
    BR_0115,

    #[strum(to_string = "Invalid claim type (mdoc top level only objects allowed)")]
    BR_0117,

    #[strum(to_string = "Attribute combination not allowed")]
    BR_0118,

    #[strum(to_string = "Trust entity not found")]
    BR_0121,

    #[strum(to_string = "Trust anchor type is not Simple Trust List")]
    BR_0122,

    #[strum(to_string = "trustAnchorId and entityId are already present")]
    BR_0120,

    #[strum(to_string = "Trust anchor must be publish")]
    BR_0123,

    #[strum(to_string = "Nested claims in arrays cannot be requested")]
    BR_0125,

    #[strum(to_string = "Claim schema key exceeded max length (255)")]
    BR_0126,

    #[strum(to_string = "DID method is not supported for issuance of this credential format")]
    BR_0127,

    #[strum(to_string = "Unsupported key type for CSR")]
    BR_0128,

    #[strum(to_string = "Incorrect disclosure level")]
    BR_0130,

    #[strum(to_string = "Trust management provider not found")]
    BR_0132,

    #[strum(to_string = "Credential schema: Duplicit claim schema")]
    BR_0133,

    #[strum(to_string = "Imported proof schema error")]
    BR_0135,

    #[strum(to_string = "Missing MDOC doctype")]
    BR_0138,

    #[strum(to_string = "Schema ID not allowed")]
    BR_0139,

    #[strum(to_string = "Validity constraint must be specified for LVVC revocation method")]
    BR_0140,

    #[strum(to_string = "No default transport specified")]
    BR_0142,

    #[strum(to_string = "Schema id not allowed for credential schema")]
    BR_0146,
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
            ServiceError::ExchangeProtocolError(error) => error.error_code(),
            ServiceError::CryptoError(_) => ErrorCode::BR_0050,
            ServiceError::FormatterError(error) => error.error_code(),
            ServiceError::KeyStorageError(_) | ServiceError::KeyStorage(_) => ErrorCode::BR_0039,
            ServiceError::MappingError(_) => ErrorCode::BR_0047,
            ServiceError::OpenID4VCError(_) => ErrorCode::BR_0048,
            ServiceError::ConfigValidationError(error) => error.error_code(),
            ServiceError::BitstringError(_) => ErrorCode::BR_0049,
            ServiceError::MissingSigner(_) => ErrorCode::BR_0060,
            ServiceError::MissingAlgorithm(_) => ErrorCode::BR_0061,
            ServiceError::MissingExchangeProtocol(_) => ErrorCode::BR_0046,
            ServiceError::KeyAlgorithmError(_) => ErrorCode::BR_0063,
            ServiceError::KeyAlgorithmProviderError(_) => ErrorCode::BR_0063,
            ServiceError::DidMethodError(_) => ErrorCode::BR_0064,
            ServiceError::ValidationError(_) | ServiceError::Other(_) => ErrorCode::BR_0000,
            ServiceError::Revocation(_) => ErrorCode::BR_0101,
        }
    }
}

impl ConfigValidationError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ConfigValidationError::TypeNotFound(_) => ErrorCode::BR_0089,
            ConfigValidationError::InvalidKey(_)
            | ConfigValidationError::KeyDisabled(_)
            | ConfigValidationError::KeyNotFound(_)
            | ConfigValidationError::FieldsDeserialization { .. }
            | ConfigValidationError::InvalidType(_, _)
            | ConfigValidationError::DatatypeValidation(_) => ErrorCode::BR_0051,
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
            EntityNotFoundError::Proof(_) => ErrorCode::BR_0012,
            EntityNotFoundError::Organisation(_) => ErrorCode::BR_0022,
            EntityNotFoundError::Key(_) => ErrorCode::BR_0037,
            EntityNotFoundError::CredentialSchema(_) => ErrorCode::BR_0006,
            EntityNotFoundError::Lvvc(_) => ErrorCode::BR_0000,
            EntityNotFoundError::History(_) => ErrorCode::BR_0100,
            EntityNotFoundError::TrustAnchor(_) => ErrorCode::BR_0115,
            EntityNotFoundError::TrustEntity(_) => ErrorCode::BR_0121,
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
            BusinessLogicError::MissingParentClaimSchema { .. } => ErrorCode::BR_0109,
            BusinessLogicError::MissingRevocationListForDid { .. } => ErrorCode::BR_0035,
            BusinessLogicError::MissingProofSchema { .. } => ErrorCode::BR_0020,
            BusinessLogicError::MissingInteractionForAccessToken { .. } => ErrorCode::BR_0033,
            BusinessLogicError::MissingCredentialIndexOnRevocationList { .. } => ErrorCode::BR_0036,
            BusinessLogicError::MissingClaimSchemas => ErrorCode::BR_0011,
            BusinessLogicError::DidDeactivation(error) => error.error_code(),
            BusinessLogicError::KeyAlreadyExists => ErrorCode::BR_0066,
            BusinessLogicError::GeneralInputValidationError => ErrorCode::BR_0084,
            BusinessLogicError::MissingOrganisation(_) => ErrorCode::BR_0088,
            BusinessLogicError::MissingProofForInteraction(_) => ErrorCode::BR_0094,
            BusinessLogicError::StatusList2021NotSupported => ErrorCode::BR_0095,
            BusinessLogicError::CredentialAlreadyRevoked => ErrorCode::BR_0092,
            BusinessLogicError::UnfulfilledWalletStorageType => ErrorCode::BR_0097,
            BusinessLogicError::OperationNotSupportedByRevocationMethod { .. } => {
                ErrorCode::BR_0098
            }
            BusinessLogicError::CredentialIsRevokedOrSuspended => ErrorCode::BR_0099,
            BusinessLogicError::RevocationMethodNotCompatibleWithSelectedFormat => {
                ErrorCode::BR_0110
            }
            BusinessLogicError::IncompatibleIssuanceDidMethod => ErrorCode::BR_0127,
            BusinessLogicError::IncompatibleIssuanceExchangeProtocol => ErrorCode::BR_0111,
            BusinessLogicError::IncompatibleProofExchangeProtocol => ErrorCode::BR_0112,
            BusinessLogicError::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed => {
                ErrorCode::BR_0117
            }
            BusinessLogicError::ClaimSchemaKeyTooLong => ErrorCode::BR_0126,
            BusinessLogicError::UnsupportedKeyTypeForCSR => ErrorCode::BR_0128,
            BusinessLogicError::IncorrectDisclosureLevel => ErrorCode::BR_0130,
            BusinessLogicError::TrustAnchorNameTaken => ErrorCode::BR_0113,
            BusinessLogicError::UnknownTrustAnchorType => ErrorCode::BR_0114,
            BusinessLogicError::TrustAnchorMustBePublish => ErrorCode::BR_0123,
            BusinessLogicError::TrustEntityAlreadyPresent => ErrorCode::BR_0120,
            BusinessLogicError::TrustAnchorTypeIsNotSimpleTrustList => ErrorCode::BR_0122,
            BusinessLogicError::ProofSchemaImport(_) => ErrorCode::BR_0135,
            BusinessLogicError::MissingMdocDoctype => ErrorCode::BR_0138,
            BusinessLogicError::SchemaIdNotAllowed => ErrorCode::BR_0139,
        }
    }
}

impl ValidationError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ValidationError::InvalidExchangeType { .. } => ErrorCode::BR_0052,
            ValidationError::MissingDefaultTransport => ErrorCode::BR_0142,
            ValidationError::SchemaIdNotAllowedForFormat => ErrorCode::BR_0146,
            ValidationError::UnsupportedKeyType { .. } => ErrorCode::BR_0053,
            ValidationError::DidInvalidKeyNumber => ErrorCode::BR_0030,
            ValidationError::CredentialSchemaMissingClaims => ErrorCode::BR_0008,
            ValidationError::CredentialMissingClaim { .. } => ErrorCode::BR_0003,
            ValidationError::CredentialSchemaDuplicitClaim => ErrorCode::BR_0133,
            ValidationError::ProofSchemaMissingClaims => ErrorCode::BR_0016,
            ValidationError::ProofSchemaNoRequiredClaim => ErrorCode::BR_0017,
            ValidationError::ProofSchemaDuplicitClaim => ErrorCode::BR_0018,
            ValidationError::InvalidFormatter(_) => ErrorCode::BR_0056,
            ValidationError::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            ValidationError::InvalidKey(_) => ErrorCode::BR_0096,
            ValidationError::BBSNotSupported => ErrorCode::BR_0091,
            ValidationError::InvalidKeyStorage(_) => ErrorCode::BR_0041,
            ValidationError::UnsupportedKeyOperation => ErrorCode::BR_0041,
            ValidationError::InvalidDatatype { .. } => ErrorCode::BR_0061,
            ValidationError::DidNotFound => ErrorCode::BR_0024,
            ValidationError::KeyNotFound => ErrorCode::BR_0037,
            ValidationError::ProofSchemaMissingProofInputSchemas => ErrorCode::BR_0104,
            ValidationError::CredentialSchemaMissingNestedClaims(_) => ErrorCode::BR_0106,
            ValidationError::CredentialSchemaNestedClaimsShouldBeEmpty(_) => ErrorCode::BR_0107,
            ValidationError::CredentialSchemaClaimSchemaSlashInKeyName(_) => ErrorCode::BR_0108,
            ValidationError::MissingLayoutAttribute(_) => ErrorCode::BR_0105,
            ValidationError::AttributeCombinationNotAllowed => ErrorCode::BR_0118,
            ValidationError::ValidityConstraintMissingForLvvc => ErrorCode::BR_0140,
            ValidationError::CertificateRequestedForMoreThan457Days => ErrorCode::BR_0084,
            ValidationError::NestedClaimInArrayRequested => ErrorCode::BR_0125,
        }
    }
}

impl ExchangeProtocolError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ExchangeProtocolError::Failed(_) => ErrorCode::BR_0062,
            ExchangeProtocolError::IncorrectCredentialSchemaType => ErrorCode::BR_0087,
            ExchangeProtocolError::HttpRequestError(_) => ErrorCode::BR_0086,
            ExchangeProtocolError::HttpResponse(_) => ErrorCode::BR_0086,
            ExchangeProtocolError::JsonError(_) => ErrorCode::BR_0062,
            ExchangeProtocolError::OperationNotSupported => ErrorCode::BR_0062,
            ExchangeProtocolError::MissingBaseUrl => ErrorCode::BR_0062,
            ExchangeProtocolError::InvalidRequest(_) => ErrorCode::BR_0085,
        }
    }
}

impl FormatterError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            FormatterError::BBSOnly => ErrorCode::BR_0090,
            FormatterError::Failed(_)
            | FormatterError::CouldNotSign(_)
            | FormatterError::CouldNotVerify(_)
            | FormatterError::CouldNotFormat(_)
            | FormatterError::CouldNotExtractCredentials(_)
            | FormatterError::CouldNotExtractPresentation(_)
            | FormatterError::CouldNotExtractClaimsFromPresentation(_)
            | FormatterError::IncorrectSignature
            | FormatterError::MissingPart
            | FormatterError::MissingDisclosure
            | FormatterError::MissingIssuer
            | FormatterError::MissingClaim
            | FormatterError::CryptoError(_)
            | FormatterError::MissingBaseUrl { .. }
            | FormatterError::JsonMapping(_)
            | FormatterError::JsonPtrMalformed(_)
            | FormatterError::JsonPtrError(_)
            | FormatterError::FloatValueIsNaN => ErrorCode::BR_0057,
        }
    }
}
