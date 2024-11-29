use one_crypto::CryptoProviderError;
use shared_types::{
    ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, DidValue, HistoryId, KeyId,
    OrganisationId, ProofId, ProofSchemaId, TrustAnchorId, TrustEntityId,
};
use strum::Display;
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
use crate::provider::did_method::error::{DidMethodError, DidMethodProviderError};
use crate::provider::did_method::mdl::DidMdlValidationError;
use crate::provider::exchange_protocol::error::{ExchangeProtocolError, TxCodeError};
use crate::provider::exchange_protocol::openid4vc::error::{OpenID4VCError, OpenID4VCIError};
use crate::provider::key_algorithm::error::{KeyAlgorithmError, KeyAlgorithmProviderError};
use crate::provider::key_storage::error::{KeyStorageError, KeyStorageProviderError};
use crate::provider::revocation::bitstring_status_list::util::BitstringError;
use crate::provider::revocation::error::RevocationError;
use crate::provider::trust_management::error::TrustManagementError;
use crate::repository::error::DataLayerError;
use crate::util::oidc::FormatError;

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

    #[error("Did method error `{0}`")]
    DidMethodError(#[from] DidMethodError),

    #[error("Did method provider error `{0}`")]
    DidMethodProviderError(#[from] DidMethodProviderError),

    #[error("Did mdl validation error `{0}`")]
    DidMdlValidationError(#[from] DidMdlValidationError),

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
    KeyStorageError(#[from] KeyStorageError),

    #[error(transparent)]
    KeyStorageProvider(#[from] KeyStorageProviderError),

    #[error("Response mapping error: {0}")]
    ResponseMapping(String),

    #[error("Revocation error: {0}")]
    Revocation(#[from] RevocationError),

    #[error("Trust management error `{0}`")]
    TrustManagementError(#[from] TrustManagementError),
}

#[derive(Debug, thiserror::Error)]
pub enum EntityNotFoundError {
    #[error("Credential `{0}` not found")]
    Credential(CredentialId),

    #[error("Did `{0}` not found")]
    Did(DidId),

    #[error("Did value `{0}` not found")]
    DidValue(DidValue),

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

    #[error("SD-JWT VC type metadata `{0}` not found")]
    SdJwtVcTypeMetadata(String),

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

    #[error("Suspension not supported for revocation method")]
    SuspensionNotAvailableForSelectedRevocationMethod,

    #[error("Incompatible issuance did method")]
    IncompatibleIssuanceDidMethod,

    #[error("Incompatible issuance exchange protocol")]
    IncompatibleIssuanceExchangeProtocol,

    #[error("Incompatible proof exchange protocol")]
    IncompatibleProofExchangeProtocol,

    #[error("Incompatible proof verfication key storage")]
    IncompatibleProofVerificationKeyStorage,

    #[error("Invalid claim type (mdoc top level only objects allowed)")]
    InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed,

    #[error("Missing schema ID")]
    MissingSchemaId,

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

    #[error("Error while importing proof request schema: {0}")]
    ProofSchemaImport(#[from] ProofSchemaImportError),

    #[error("Layout properties are not supported")]
    LayoutPropertiesNotSupported,

    #[error("Multiple matching trust anchors")]
    MultipleMatchingTrustAnchors,

    #[error("Trust entity has duplicates")]
    TrustEntityHasDuplicates,

    #[error("Trust anchor is disabled")]
    TrustAnchorIsDisabled,
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

    #[error("Proof schema: Claim schemas must not be empty")]
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

    #[error("Nested claims in arrays cannot be requested")]
    NestedClaimInArrayRequested,

    #[error("Validity constraint must be specified for LVVC revocation method")]
    ValidityConstraintMissingForLvvc,

    #[error("Invalid SCAN_TO_VERIFY parameters")]
    InvalidScanToVerifyParameters,

    #[error("Schema id not allowed for format")]
    SchemaIdNotAllowedForFormat,

    #[error("Proof schema must contain only one physical card credential schema")]
    OnlyOnePhysicalCardSchemaAllowedPerProof,

    #[error("Forbidden claim name")]
    ForbiddenClaimName,

    #[error("Invalid mdl parameters")]
    InvalidMdlParameters,

    #[error("Sharing not supported for requested proof-schema")]
    ProofSchemaSharingNotSupported,

    #[error("ValidityConstraintOutOfRange")]
    ValidityConstraintOutOfRange,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Invalid update request")]
    InvalidUpdateRequest,

    #[error("Deserialization error: `{0}`")]
    DeserializationError(String),
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

impl MissingProviderError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Formatter(_) => ErrorCode::BR_0038,
            Self::KeyStorage(_) => ErrorCode::BR_0040,
            Self::DidMethod(_) => ErrorCode::BR_0031,
            Self::KeyAlgorithm(_) => ErrorCode::BR_0042,
            Self::KeyAlgorithmProvider(_) => ErrorCode::BR_0042,
            Self::RevocationMethod(_) => ErrorCode::BR_0044,
            Self::RevocationMethodByCredentialStatusType(_) => ErrorCode::BR_0045,
            Self::ExchangeProtocol(_) => ErrorCode::BR_0046,
            Self::Task(_) => ErrorCode::BR_0103,
            Self::TrustManager(_) => ErrorCode::BR_0132,
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

    #[strum(to_string = "Proof schema: no required claim")]
    BR_0017,

    #[strum(to_string = "Proof schema: duplicate claim schema")]
    BR_0018,

    #[strum(to_string = "Proof schema deleted")]
    BR_0019,

    #[strum(to_string = "Missing proof schema")]
    BR_0020,

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

    #[strum(to_string = "Model mapping error")]
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

    #[strum(to_string = "Provided datatype is invalid or value does not match the expected type")]
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

    #[strum(to_string = "Invalid claim type (mdoc: root level claims must be objects)")]
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

    #[strum(to_string = "Layout properties are not supported")]
    BR_0131,

    #[strum(to_string = "Trust management provider not found")]
    BR_0132,

    #[strum(to_string = "Credential schema: Duplicit claim schema")]
    BR_0133,

    #[strum(to_string = "Imported proof schema error")]
    BR_0135,

    #[strum(to_string = "Proof schema must contain only one physical card credential schema")]
    BR_0137,

    #[strum(to_string = "Missing Schema ID")]
    BR_0138,

    #[strum(to_string = "Schema ID not allowed")]
    BR_0139,

    #[strum(to_string = "Validity constraint must be specified for LVVC revocation method")]
    BR_0140,

    #[strum(to_string = "No default transport specified")]
    BR_0142,

    #[strum(to_string = "Invalid SCAN_TO_VERIFY parameters")]
    BR_0144,

    #[strum(to_string = "Forbidden claim name")]
    BR_0145,

    #[strum(to_string = "Schema id not allowed for credential schema")]
    BR_0146,

    #[strum(to_string = "Invalid mdl request")]
    BR_0147,

    #[strum(to_string = "Public key not matching key in core")]
    BR_0156,

    #[strum(to_string = "Certificate not signed by MDOC")]
    BR_0157,

    #[strum(to_string = "Key storage not supported for proof request")]
    BR_0158,

    #[strum(to_string = "Transport combination not allowed for exchange protocol")]
    BR_0159,

    #[strum(to_string = "No suitable transport protocol found on verifier/holder")]
    BR_0160,

    #[strum(to_string = "Suspension not supported for revocation method")]
    BR_0162,

    #[strum(to_string = "Sharing not supported to this proof schema")]
    BR_0163,

    #[strum(to_string = "Proof schema: claim schemas empty")]
    BR_0164,

    #[strum(to_string = "Validity constraint out of range")]
    BR_0166,

    #[strum(to_string = "User Provided incorrect user code")]
    BR_0169,

    #[strum(to_string = "Invalid Transaction Code Use")]
    BR_0170,

    #[strum(to_string = "SD-JWT VC type metadata not found")]
    BR_0172,

    #[strum(
        to_string = "Proof of possession of issuer did for issued credential could not be verified"
    )]
    BR_0173,

    #[strum(to_string = "Invalid create trust anchor request")]
    BR_0177,

    #[strum(to_string = "Unauthorized")]
    BR_0178,

    #[strum(to_string = "Multiple matching trust anchors")]
    BR_0179,

    #[strum(to_string = "Trust entity has duplicates")]
    BR_0180,

    #[strum(to_string = "Invalid update request")]
    BR_0181,

    #[strum(to_string = "Initialization error")]
    BR_0183,

    #[strum(to_string = "Not initialized")]
    BR_0184,

    #[strum(to_string = "Unable to resolve trust entity by did")]
    BR_0185,

    #[strum(to_string = "No trust entity found for the given did")]
    BR_0186,

    #[strum(to_string = "Trust anchor is disabled")]
    BR_0187,

    #[strum(to_string = "Trust anchor must be client")]
    BR_0188,

    #[strum(to_string = "JSON deserialization error")]
    BR_0189,
}

impl From<FormatError> for ServiceError {
    fn from(value: FormatError) -> Self {
        match value {
            FormatError::MappingError(value) => Self::MappingError(value),
        }
    }
}

impl From<uuid::Error> for ServiceError {
    fn from(value: uuid::Error) -> Self {
        Self::MappingError(value.to_string())
    }
}

pub trait ErrorCodeMixin {
    fn error_code(&self) -> ErrorCode;
}

impl ErrorCodeMixin for ServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::EntityNotFound(error) => error.error_code(),
            Self::BusinessLogic(error) => error.error_code(),
            Self::Validation(error) => error.error_code(),
            Self::Repository(error) => error.error_code(),
            Self::MissingProvider(error) => error.error_code(),
            Self::ResponseMapping(_) => ErrorCode::BR_0055,
            Self::ExchangeProtocolError(error) => error.error_code(),
            Self::CryptoError(_) => ErrorCode::BR_0050,
            Self::FormatterError(error) => error.error_code(),
            Self::KeyStorageError(_) | Self::KeyStorageProvider(_) => ErrorCode::BR_0039,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::OpenID4VCError(_) | Self::OpenID4VCIError(_) => ErrorCode::BR_0048,
            Self::ConfigValidationError(error) => error.error_code(),
            Self::BitstringError(_) => ErrorCode::BR_0049,
            Self::MissingSigner(_) => ErrorCode::BR_0060,
            Self::MissingAlgorithm(_) => ErrorCode::BR_0061,
            Self::MissingExchangeProtocol(_) => ErrorCode::BR_0046,
            Self::KeyAlgorithmError(_) => ErrorCode::BR_0063,
            Self::KeyAlgorithmProviderError(_) => ErrorCode::BR_0063,
            Self::DidMethodError(_) => ErrorCode::BR_0064,
            Self::DidMethodProviderError(error) => error.error_code(),
            Self::DidMdlValidationError(error) => error.error_code(),
            Self::ValidationError(_) | Self::Other(_) => ErrorCode::BR_0000,
            Self::Revocation(_) => ErrorCode::BR_0101,
            Self::TrustManagementError(_) => ErrorCode::BR_0185,
        }
    }
}

impl ErrorCodeMixin for ConfigValidationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::TypeNotFound(_) => ErrorCode::BR_0089,
            Self::EntryDisabled(_)
            | Self::EntryNotFound(_)
            | Self::FieldsDeserialization { .. }
            | Self::InvalidType(_, _)
            | Self::DatatypeValidation(_) => ErrorCode::BR_0051,
        }
    }
}

impl ErrorCodeMixin for EntityNotFoundError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Credential(_) => ErrorCode::BR_0001,
            Self::Did(_) | Self::DidValue(_) => ErrorCode::BR_0024,
            Self::RevocationList(_) => ErrorCode::BR_0034,
            Self::ProofSchema(_) => ErrorCode::BR_0014,
            Self::Proof(_) => ErrorCode::BR_0012,
            Self::Organisation(_) => ErrorCode::BR_0022,
            Self::Key(_) => ErrorCode::BR_0037,
            Self::CredentialSchema(_) => ErrorCode::BR_0006,
            Self::Lvvc(_) => ErrorCode::BR_0000,
            Self::History(_) => ErrorCode::BR_0100,
            Self::TrustAnchor(_) => ErrorCode::BR_0115,
            Self::TrustEntity(_) => ErrorCode::BR_0121,
            Self::SdJwtVcTypeMetadata(_) => ErrorCode::BR_0172,
        }
    }
}

impl ErrorCodeMixin for BusinessLogicError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::OrganisationAlreadyExists => ErrorCode::BR_0023,
            Self::IncompatibleDidType { .. } => ErrorCode::BR_0025,
            Self::DidMethodIncapableKeyAlgorithm { .. } => ErrorCode::BR_0065,
            Self::InvalidDidMethod { .. } => ErrorCode::BR_0026,
            Self::DidIsDeactivated(_) => ErrorCode::BR_0027,
            Self::DidValueAlreadyExists(_) => ErrorCode::BR_0028,
            Self::CredentialSchemaAlreadyExists => ErrorCode::BR_0007,
            Self::InvalidCredentialState { .. } => ErrorCode::BR_0002,
            Self::ProofSchemaAlreadyExists => ErrorCode::BR_0015,
            Self::InvalidProofState { .. } => ErrorCode::BR_0013,
            Self::MissingCredentialsForInteraction { .. } => ErrorCode::BR_0004,
            Self::ProofSchemaDeleted { .. } => ErrorCode::BR_0019,
            Self::MissingCredentialData { .. } => ErrorCode::BR_0005,
            Self::MissingCredentialSchema => ErrorCode::BR_0009,
            Self::MissingClaimSchema { .. } => ErrorCode::BR_0010,
            Self::MissingParentClaimSchema { .. } => ErrorCode::BR_0109,
            Self::MissingRevocationListForDid { .. } => ErrorCode::BR_0035,
            Self::MissingProofSchema { .. } => ErrorCode::BR_0020,
            Self::MissingInteractionForAccessToken { .. } => ErrorCode::BR_0033,
            Self::MissingCredentialIndexOnRevocationList { .. } => ErrorCode::BR_0036,
            Self::MissingClaimSchemas => ErrorCode::BR_0011,
            Self::DidDeactivation(error) => error.error_code(),
            Self::KeyAlreadyExists => ErrorCode::BR_0066,
            Self::GeneralInputValidationError => ErrorCode::BR_0084,
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::MissingProofForInteraction(_) => ErrorCode::BR_0094,
            Self::StatusList2021NotSupported => ErrorCode::BR_0095,
            Self::CredentialAlreadyRevoked => ErrorCode::BR_0092,
            Self::UnfulfilledWalletStorageType => ErrorCode::BR_0097,
            Self::OperationNotSupportedByRevocationMethod { .. } => ErrorCode::BR_0098,
            Self::CredentialIsRevokedOrSuspended => ErrorCode::BR_0099,
            Self::RevocationMethodNotCompatibleWithSelectedFormat => ErrorCode::BR_0110,
            Self::IncompatibleIssuanceDidMethod => ErrorCode::BR_0127,
            Self::IncompatibleIssuanceExchangeProtocol => ErrorCode::BR_0111,
            Self::IncompatibleProofExchangeProtocol => ErrorCode::BR_0112,
            Self::IncompatibleProofVerificationKeyStorage => ErrorCode::BR_0158,
            Self::InvalidClaimTypeMdocTopLevelOnlyObjectsAllowed => ErrorCode::BR_0117,
            Self::ClaimSchemaKeyTooLong => ErrorCode::BR_0126,
            Self::UnsupportedKeyTypeForCSR => ErrorCode::BR_0128,
            Self::IncorrectDisclosureLevel => ErrorCode::BR_0130,
            Self::TrustAnchorNameTaken => ErrorCode::BR_0113,
            Self::UnknownTrustAnchorType => ErrorCode::BR_0114,
            Self::TrustAnchorMustBePublish => ErrorCode::BR_0123,
            Self::TrustAnchorMustBeClient => ErrorCode::BR_0188,
            Self::TrustAnchorInvalidCreateRequest { .. } => ErrorCode::BR_0177,
            Self::TrustEntityAlreadyPresent => ErrorCode::BR_0120,
            Self::TrustAnchorTypeIsNotSimpleTrustList => ErrorCode::BR_0122,
            Self::ProofSchemaImport(_) => ErrorCode::BR_0135,
            Self::MissingSchemaId => ErrorCode::BR_0138,
            Self::SchemaIdNotAllowed => ErrorCode::BR_0139,
            Self::LayoutPropertiesNotSupported => ErrorCode::BR_0131,
            Self::SuspensionNotAvailableForSelectedRevocationMethod => ErrorCode::BR_0162,
            Self::MultipleMatchingTrustAnchors => ErrorCode::BR_0179,
            Self::TrustEntityHasDuplicates => ErrorCode::BR_0180,
            Self::TrustAnchorIsDisabled => ErrorCode::BR_0187,
            Self::MissingTrustEntity(_) => ErrorCode::BR_0186,
        }
    }
}

impl ErrorCodeMixin for ValidationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidExchangeType { .. } => ErrorCode::BR_0052,
            Self::MissingDefaultTransport => ErrorCode::BR_0142,
            Self::SchemaIdNotAllowedForFormat => ErrorCode::BR_0146,
            Self::UnsupportedKeyType { .. } => ErrorCode::BR_0053,
            Self::DidInvalidKeyNumber => ErrorCode::BR_0030,
            Self::CredentialSchemaMissingClaims => ErrorCode::BR_0008,
            Self::CredentialMissingClaim { .. } => ErrorCode::BR_0003,
            Self::CredentialSchemaDuplicitClaim => ErrorCode::BR_0133,
            Self::ProofSchemaMissingClaims => ErrorCode::BR_0164,
            Self::ProofSchemaNoRequiredClaim => ErrorCode::BR_0017,
            Self::ProofSchemaDuplicitClaim => ErrorCode::BR_0018,
            Self::InvalidFormatter(_) => ErrorCode::BR_0056,
            Self::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            Self::InvalidKey(_) => ErrorCode::BR_0096,
            Self::BBSNotSupported => ErrorCode::BR_0091,
            Self::InvalidKeyStorage(_) => ErrorCode::BR_0041,
            Self::UnsupportedKeyOperation => ErrorCode::BR_0041,
            Self::InvalidDatatype { .. } => ErrorCode::BR_0061,
            Self::DidNotFound => ErrorCode::BR_0024,
            Self::KeyNotFound => ErrorCode::BR_0037,
            Self::ProofSchemaMissingProofInputSchemas => ErrorCode::BR_0104,
            Self::CredentialSchemaMissingNestedClaims(_) => ErrorCode::BR_0106,
            Self::CredentialSchemaNestedClaimsShouldBeEmpty(_) => ErrorCode::BR_0107,
            Self::CredentialSchemaClaimSchemaSlashInKeyName(_) => ErrorCode::BR_0108,
            Self::MissingLayoutAttribute(_) => ErrorCode::BR_0105,
            Self::AttributeCombinationNotAllowed => ErrorCode::BR_0118,
            Self::ValidityConstraintMissingForLvvc => ErrorCode::BR_0140,
            Self::InvalidScanToVerifyParameters => ErrorCode::BR_0144,
            Self::NestedClaimInArrayRequested => ErrorCode::BR_0125,
            Self::OnlyOnePhysicalCardSchemaAllowedPerProof => ErrorCode::BR_0137,
            Self::ForbiddenClaimName => ErrorCode::BR_0145,
            Self::InvalidMdlParameters => ErrorCode::BR_0147,
            Self::ProofSchemaSharingNotSupported => ErrorCode::BR_0163,
            Self::TransportNotAllowedForExchange => ErrorCode::BR_0160,
            Self::TransportsCombinationNotAllowed => ErrorCode::BR_0159,
            Self::InvalidTransportType { .. } => ErrorCode::BR_0112,
            Self::ValidityConstraintOutOfRange => ErrorCode::BR_0166,
            Self::Unauthorized => ErrorCode::BR_0178,
            Self::InvalidUpdateRequest => ErrorCode::BR_0181,
            Self::DeserializationError(_) => ErrorCode::BR_0189,
        }
    }
}

impl ErrorCodeMixin for ExchangeProtocolError {
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
            ExchangeProtocolError::DidMismatch
            | ExchangeProtocolError::CredentialVerificationFailed(_) => ErrorCode::BR_0173,
        }
    }
}

impl ErrorCodeMixin for FormatterError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::BBSOnly => ErrorCode::BR_0090,
            Self::Failed(_)
            | Self::CouldNotSign(_)
            | Self::CouldNotVerify(_)
            | Self::CouldNotFormat(_)
            | Self::CouldNotExtractCredentials(_)
            | Self::CouldNotExtractPresentation(_)
            | Self::CouldNotExtractClaimsFromPresentation(_)
            | Self::IncorrectSignature
            | Self::MissingPart
            | Self::MissingDisclosure
            | Self::MissingIssuer
            | Self::MissingHolder
            | Self::MissingClaim
            | Self::CryptoError(_)
            | Self::MissingBaseUrl { .. }
            | Self::JsonMapping(_)
            | Self::JsonPtrAssignError(_)
            | Self::JsonPtrParseError(_)
            | Self::FloatValueIsNaN => ErrorCode::BR_0057,
        }
    }
}

impl ErrorCodeMixin for DidMethodProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::DidMethod(_)
            | Self::CachingLoader(_)
            | Self::FailedToResolve(_)
            | Self::JsonParse(_)
            | Self::MissingDidMethodNameInDidValue
            | Self::RemoteEntityStorage(_)
            | Self::VerificationMethodIdNotFound { .. }
            | Self::Other(_) => ErrorCode::BR_0064,
            Self::MissingProvider(_) => ErrorCode::BR_0031,
        }
    }
}

impl ErrorCodeMixin for DidMdlValidationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::CertificateSignatureVerificationFailed(_) | Self::CertificateExpired => {
                ErrorCode::BR_0157
            }
            Self::SubjectPublicKeyNotMatching
            | Self::KeyTypeNotSupported(_)
            | Self::SubjectPublicKeyInvalidDer(_) => ErrorCode::BR_0156,
        }
    }
}
