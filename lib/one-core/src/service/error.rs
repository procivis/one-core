use one_crypto::CryptoProviderError;
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, DidValue, HistoryId,
    IdentifierId, KeyId, OrganisationId, ProofId, ProofSchemaId, TrustAnchorId, TrustEntityId,
    TrustEntityKey, WalletUnitId,
};
use strum::{EnumMessage, IntoStaticStr};
use thiserror::Error;
use uuid::Uuid;

use super::did::DidDeactivationError;
use super::proof_schema::ProofSchemaImportError;
use crate::config::ConfigValidationError;
use crate::config::core_config::VerificationProtocolType;
use crate::model::credential::{CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::model::did::KeyRole;
use crate::model::interaction::InteractionId;
use crate::model::proof::{ProofRole, ProofStateEnum};
use crate::model::revocation_list::RevocationListId;
use crate::proto::nfc::NfcError;
use crate::provider::blob_storage_provider::error::BlobStorageError;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::did_method::error::{DidMethodError, DidMethodProviderError};
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError, TxCodeError,
};
use crate::provider::key_algorithm::error::{KeyAlgorithmError, KeyAlgorithmProviderError};
use crate::provider::key_algorithm::key::KeyHandleError;
use crate::provider::key_storage::error::{KeyStorageError, KeyStorageProviderError};
use crate::provider::revocation::bitstring_status_list::util::BitstringError;
use crate::provider::revocation::error::RevocationError;
use crate::provider::trust_management::error::TrustManagementError;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::repository::error::DataLayerError;
use crate::service::wallet_provider::error::WalletProviderError;
use crate::service::wallet_unit::error::WalletUnitAttestationError;

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

    #[error("Config validation error `{0}`")]
    ConfigValidationError(#[from] ConfigValidationError),

    #[error("Issuance protocol error `{0}`")]
    IssuanceProtocolError(#[from] IssuanceProtocolError),

    #[error("Verification protocol error `{0}`")]
    VerificationProtocolError(#[from] VerificationProtocolError),

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

    #[error(transparent)]
    KeyHandleError(#[from] KeyHandleError),

    #[error("Did method error `{0}`")]
    DidMethodError(#[from] DidMethodError),

    #[error("Did method provider error `{0}`")]
    DidMethodProviderError(#[from] DidMethodProviderError),

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

    #[error("Revocation error: {0}")]
    Revocation(#[from] RevocationError),

    #[error("Trust management error `{0}`")]
    TrustManagementError(#[from] TrustManagementError),

    #[error("Blob storage error `{0}`")]
    BlobStorageError(#[from] BlobStorageError),

    #[error("Wallet provider error: `{0}`")]
    WalletProviderError(#[from] WalletProviderError),

    #[error("Wallet unit error: `{0}`")]
    WalletUnitAttestationError(#[from] WalletUnitAttestationError),

    #[error("NFC error: `{0}`")]
    NfcError(#[from] NfcError),
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

    #[error("Certificate `{0}` not found")]
    Certificate(CertificateId),

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

    #[error("Trust entity by entity key `{0}` not found")]
    TrustEntityByEntityKey(TrustEntityKey),

    #[error("Interaction `{0}` not found")]
    Interaction(InteractionId),

    #[error("Wallet unit `{0}` not found")]
    WalletUnit(WalletUnitId),

    #[error("Wallet unit attestation by organisation `{0}` not found")]
    WalletUnitAttestationByOrganisation(OrganisationId),
}

#[derive(Debug, thiserror::Error)]
pub enum BusinessLogicError {
    #[error("Organisation already exists")]
    OrganisationAlreadyExists,

    #[error("Organisation {0} is deactivated")]
    OrganisationIsDeactivated(OrganisationId),

    #[error("Organisation not specified")]
    OrganisationNotSpecified,

    #[error("Incompatible DID type, reason: {reason}")]
    IncompatibleDidType { reason: String },

    #[error("Incompatible identifier type, reason: {reason}")]
    IncompatibleIdentifierType { reason: String },

    #[error("DID {0} is deactivated")]
    DidIsDeactivated(DidId),

    #[error("Identifier {0} is deactivated")]
    IdentifierIsDeactivated(IdentifierId),

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

    #[error("Invalid proof role: {role}")]
    InvalidProofRole { role: ProofRole },

    #[error("Cannot retract proof with exchange type: {exchange_type}")]
    InvalidProofExchangeForRetraction {
        exchange_type: VerificationProtocolType,
    },

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

    #[error("Credential role must be Holder, received {role}, credential id: {credential_id}")]
    RevocationCheckNotAllowedForRole {
        role: CredentialRole,
        credential_id: CredentialId,
    },

    #[error("Wallet storage type requirement cannot be fulfilled")]
    UnfulfilledWalletStorageType,

    #[error("Credential state is Revoked or Suspended and cannot be shared")]
    CredentialIsRevokedOrSuspended,

    #[error("Revocation method not compatible with selected format")]
    RevocationMethodNotCompatibleWithSelectedFormat,

    #[error("Suspension not supported for revocation method")]
    SuspensionNotAvailableForSelectedRevocationMethod,

    #[error("Suspension not enabled for suspend-only revocation method")]
    SuspensionNotEnabledForSuspendOnlyRevocationMethod,

    #[error("Incompatible issuance did method")]
    IncompatibleIssuanceDidMethod,

    #[error("Incompatible issuance exchange protocol")]
    IncompatibleIssuanceExchangeProtocol,

    #[error("Incompatible issuance identifier")]
    IncompatibleIssuanceIdentifier,

    #[error("Incompatible proof exchange protocol")]
    IncompatibleProofExchangeProtocol,

    #[error("Incompatible proof verfication key storage")]
    IncompatibleProofVerificationKeyStorage,

    #[error("Incompatible proof verification identifier")]
    IncompatibleProofVerificationIdentifier,

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

    #[error("Overlapping holder DID with identifier")]
    OverlappingHolderDidWithIdentifier,

    #[error("Incompatible holder did method")]
    IncompatibleHolderDidMethod,

    #[error("Incompatible holder identifier")]
    IncompatibleHolderIdentifier,

    #[error("Incompatible holder key algorithm")]
    IncompatibleHolderKeyAlgorithm,

    #[error("Identifier type not found")]
    IdentifierTypeNotFound,

    #[error("Rejection not supported")]
    RejectionNotSupported,

    #[error("Identifier already exists")]
    IdentifierAlreadyExists,

    #[error("Certificate `{certificate_id}` is not associated with identifier `{identifier_id}`")]
    IdentifierCertificateIdMismatch {
        identifier_id: String,
        certificate_id: String,
    },

    #[error("Certificate id not specified")]
    CertificateIdNotSpecified,

    #[error("Certificate already exists")]
    CertificateAlreadyExists,

    #[error("Presentation submission must contain at least one credential")]
    EmptyPresentationSubmission,

    #[error("Identifier does not belong to this organisation")]
    IdentifierOrganisationMismatch,

    #[error("Wallet provider is already associated to organisation `{0}`")]
    WalletProviderAlreadyAssociated(OrganisationId),

    #[error("Invalid presentation submission: {reason}")]
    InvalidPresentationSubmission { reason: String },

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

    #[error("Credential schema: Claim `{claim_name}` data type {data_type} is unsupported")]
    CredentialSchemaClaimSchemaUnsupportedDatatype {
        claim_name: String,
        data_type: String,
    },

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

    #[error("Forbidden")]
    Forbidden,

    #[error("Invalid update request")]
    InvalidUpdateRequest,

    #[error("Deserialization error: `{0}`")]
    DeserializationError(String),

    #[error("Exchange protocol operation disabled")]
    InvalidExchangeOperation,

    #[error("Redirect uri disabled or scheme not allowed")]
    InvalidRedirectUri,

    #[error("Empty object not allowed")]
    EmptyObjectNotAllowed,

    #[error("Empty array value not allowed")]
    EmptyArrayValueNotAllowed,

    #[error("Empty value not allowed")]
    EmptyValueNotAllowed,

    #[error("Invalid image data: `{0}`")]
    InvalidImage(String),

    #[error("Missing key with role `{0}`")]
    NoKeyWithRole(KeyRole),

    #[error("DID, Key or Certificate must be specified when creating identifier")]
    InvalidIdentifierInput,

    #[error("Certificate signature invalid")]
    CertificateSignatureInvalid,

    #[error("Certificate revoked")]
    CertificateRevoked,

    #[error("Certificate is expired")]
    CertificateExpired,

    #[error("Certificate is not yet valid")]
    CertificateNotYetValid,

    #[error("Key does not match public key of certificate")]
    CertificateKeyNotMatching,

    #[error("Certificate parsing failure: `{0}`")]
    CertificateParsingFailed(String),

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

    #[error("CRL check failure: `{0}`")]
    CRLCheckFailed(String),

    #[error("CRL is not up to date")]
    CRLOutdated,

    #[error("CRL signature invalid")]
    CRLSignatureInvalid,

    #[error("Wallet storage type `{0}` not supported")]
    WalletStorageTypeDisabled(WalletStorageTypeEnum),

    #[error("Invalid CA chain: {0}")]
    InvalidCaCertificateChain(String),

    #[error("Missing authority key identifier")]
    MissingAuthorityKeyIdentifier,

    #[error("Key must not be remote: `{0}`")]
    KeyMustNotBeRemote(String),

    #[error("Unknown critical X.509 extension: {0}")]
    UnknownCriticalExtension(String),

    #[error("Certificate key usage violation: {0}")]
    KeyUsageViolation(String),

    #[error("Basic constraints violation: {0}")]
    BasicConstraintsViolation(String),

    #[error("Missing configuration for verification engagement type: {0}")]
    MissingVerificationEngagementConfig(String),

    #[error("Missing engagement for ISO mDL flow")]
    MissingEngagementForISOmDLFlow,

    #[error("Invalid value of proof engagement")]
    InvalidProofEngagement,

    #[error("Engagement provided for non ISO mDL flow")]
    EngagementProvidedForNonISOmDLFlow,
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

    #[error("Cannot find blob storage `{0}`")]
    BlobStorage(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, IntoStaticStr, EnumMessage)]
#[allow(non_camel_case_types)]
pub enum ErrorCode {
    #[strum(message = "Unmapped error code")]
    BR_0000,

    #[strum(message = "Credential not found")]
    BR_0001,

    #[strum(message = "Credential state invalid")]
    BR_0002,

    #[strum(message = "Credential: Missing claim")]
    BR_0003,

    #[strum(message = "Missing credentials for provided interaction")]
    BR_0004,

    #[strum(message = "Missing credential data for provided credential")]
    BR_0005,

    #[strum(message = "Credential schema not found")]
    BR_0006,

    #[strum(message = "Credential schema already exists")]
    BR_0007,

    #[strum(message = "Credential schema: Missing claims")]
    BR_0008,

    #[strum(message = "Missing credential schema")]
    BR_0009,

    #[strum(message = "Missing claim schema")]
    BR_0010,

    #[strum(message = "Missing claim schemas")]
    BR_0011,

    #[strum(message = "Proof not found")]
    BR_0012,

    #[strum(message = "Proof state invalid")]
    BR_0013,

    #[strum(message = "Proof schema not found")]
    BR_0014,

    #[strum(message = "Proof schema already exists")]
    BR_0015,

    #[strum(message = "Proof schema: no required claim")]
    BR_0017,

    #[strum(message = "Proof schema: duplicate claim schema")]
    BR_0018,

    #[strum(message = "Proof schema deleted")]
    BR_0019,

    #[strum(message = "Missing proof schema")]
    BR_0020,

    #[strum(message = "Organisation not found")]
    BR_0022,

    #[strum(message = "Organisation already exists")]
    BR_0023,

    #[strum(message = "DID not found")]
    BR_0024,

    #[strum(message = "Invalid DID type")]
    BR_0025,

    #[strum(message = "Invalid DID method")]
    BR_0026,

    #[strum(message = "DID deactivated")]
    BR_0027,

    #[strum(message = "DID value already exists")]
    BR_0028,

    #[strum(message = "DID cannot be deactivated")]
    BR_0029,

    #[strum(message = "DID invalid key number")]
    BR_0030,

    #[strum(message = "Missing DID method")]
    BR_0031,

    #[strum(message = "Credential schema already exists")]
    BR_0032,

    #[strum(message = "Missing interaction for access token")]
    BR_0033,

    #[strum(message = "Revocation list not found")]
    BR_0034,

    #[strum(message = "Missing revocation list for provided DID")]
    BR_0035,

    #[strum(message = "Missing credential index on revocation list")]
    BR_0036,

    #[strum(message = "Key not found")]
    BR_0037,

    #[strum(message = "Missing formatter")]
    BR_0038,

    #[strum(message = "Generic key storage error")]
    BR_0039,

    #[strum(message = "Missing key storage")]
    BR_0040,

    #[strum(message = "Invalid key storage type")]
    BR_0041,

    #[strum(message = "Missing key algorithm")]
    BR_0042,

    #[strum(message = "Invalid key algorithm type")]
    BR_0043,

    #[strum(message = "Missing revocation method")]
    BR_0044,

    #[strum(message = "Missing revocation method for the provided credential status type")]
    BR_0045,

    #[strum(message = "Missing exchange protocol")]
    BR_0046,

    #[strum(message = "Model mapping error")]
    BR_0047,

    #[strum(message = "OpenID4VC error")]
    BR_0048,

    #[strum(message = "Credential status list bitstring handling error")]
    BR_0049,

    #[strum(message = "Crypto provider error")]
    BR_0050,

    #[strum(message = "Configuration validation error")]
    BR_0051,

    #[strum(message = "Invalid exchange type")]
    BR_0052,

    #[strum(message = "Unsupported key type")]
    BR_0053,

    #[strum(message = "Database error")]
    BR_0054,

    #[strum(message = "Invalid formatter type")]
    BR_0056,

    #[strum(message = "Formatter provider error")]
    BR_0057,

    #[strum(message = "Crypto provider error")]
    BR_0058,

    #[strum(message = "Missing signer")]
    BR_0059,

    #[strum(message = "Missing signer algorithm")]
    BR_0060,

    #[strum(message = "Provided datatype is invalid or value does not match the expected type")]
    BR_0061,

    #[strum(message = "Exchange protocol provider error")]
    BR_0062,

    #[strum(message = "Key algorithm provider error")]
    BR_0063,

    #[strum(message = "DID method provider error")]
    BR_0064,

    #[strum(message = "DID method is missing key algorithm capability")]
    BR_0065,

    #[strum(message = "Key already exists")]
    BR_0066,

    #[strum(message = "Proof unauthorized")]
    BR_0071,

    #[strum(message = "Key must not be remote")]
    BR_0076,

    #[strum(message = "Verification engagement not enabled")]
    BR_0077,

    #[strum(message = "Sharing not possible with non QR_CODE engagement")]
    BR_0078,

    #[strum(message = "Engagement missing for ISO mDL flow")]
    BR_0079,

    #[strum(message = "Wallet unit must be active")]
    BR_0081,

    #[strum(message = "Invalid DCQL query or presentation definition")]
    BR_0083,

    #[strum(message = "General input validation error")]
    BR_0084,

    #[strum(message = "Invalid handle invitation received")]
    BR_0085,

    #[strum(message = "Cannot fetch credential offer or presentation definition")]
    BR_0086,

    #[strum(message = "Incorrect credential schema type")]
    BR_0087,

    #[strum(message = "Missing organisation")]
    BR_0088,

    #[strum(message = "Missing configuration entity")]
    BR_0089,

    #[strum(message = "JSON-LD: BBS key needed")]
    BR_0090,

    #[strum(message = "BBS key not supported")]
    BR_0091,

    #[strum(message = "Credential already revoked")]
    BR_0092,

    #[strum(message = "Missing proof for provided interaction")]
    BR_0094,

    #[strum(message = "StatusList2021 not supported for credential issuance and revocation")]
    BR_0095,

    #[strum(message = "Invalid key")]
    BR_0096,

    #[strum(message = "Requested wallet storage type cannot be fulfilled")]
    BR_0097,

    #[strum(message = "Revocation method does not support state (REVOKE, SUSPEND)")]
    BR_0098,

    #[strum(message = "Credential state is Revoked or Suspended and cannot be shared")]
    BR_0099,

    #[strum(message = "History event not found")]
    BR_0100,

    #[strum(message = "Revocation error")]
    BR_0101,

    #[strum(message = "Missing task")]
    BR_0103,

    #[strum(message = "Missing proof input schemas")]
    BR_0104,

    #[strum(message = "Primary/Secondary attribute does not exists")]
    BR_0105,

    #[strum(message = "Missing nested claims")]
    BR_0106,

    #[strum(message = "Nested claims should be empty")]
    BR_0107,

    #[strum(message = "Slash in claim schema key name")]
    BR_0108,

    #[strum(message = "Missing parent claim schema")]
    BR_0109,

    #[strum(message = "Revocation method not compatible")]
    BR_0110,

    #[strum(message = "Incompatible issuance exchange protocol")]
    BR_0111,

    #[strum(message = "Incompatible proof exchange protocol")]
    BR_0112,

    #[strum(message = "Trust anchor name already in use")]
    BR_0113,

    #[strum(message = "Trust anchor type not found")]
    BR_0114,

    #[strum(message = "Trust anchor not found")]
    BR_0115,

    #[strum(message = "Invalid claim type (mdoc: root level claims must be objects)")]
    BR_0117,

    #[strum(message = "Attribute combination not allowed")]
    BR_0118,

    #[strum(message = "Trust entity not found")]
    BR_0121,

    #[strum(message = "Trust anchor type is not Simple Trust List")]
    BR_0122,

    #[strum(message = "trustAnchorId and entityId are already present")]
    BR_0120,

    #[strum(message = "Trust anchor must be publish")]
    BR_0123,

    #[strum(message = "Nested claims in arrays cannot be requested")]
    BR_0125,

    #[strum(message = "Claim schema key exceeded max length (255)")]
    BR_0126,

    #[strum(message = "DID method is not supported for issuance of this credential format")]
    BR_0127,

    #[strum(message = "Unsupported key type for CSR")]
    BR_0128,

    #[strum(message = "Incorrect disclosure level")]
    BR_0130,

    #[strum(message = "Layout properties are not supported")]
    BR_0131,

    #[strum(message = "Trust management provider not found")]
    BR_0132,

    #[strum(message = "Credential schema: Duplicit claim schema")]
    BR_0133,

    #[strum(message = "Imported proof schema error")]
    BR_0135,

    #[strum(message = "Proof schema must contain only one physical card credential schema")]
    BR_0137,

    #[strum(message = "Missing Schema ID")]
    BR_0138,

    #[strum(message = "Schema ID not allowed")]
    BR_0139,

    #[strum(message = "Validity constraint must be specified for LVVC revocation method")]
    BR_0140,

    #[strum(message = "No default transport specified")]
    BR_0142,

    #[strum(message = "Invalid SCAN_TO_VERIFY parameters")]
    BR_0144,

    #[strum(message = "Forbidden claim name")]
    BR_0145,

    #[strum(message = "Schema id not allowed for credential schema")]
    BR_0146,

    #[strum(message = "Invalid mdl request")]
    BR_0147,

    #[strum(message = "Invalid wallet unit attestation nonce")]
    BR_0153,

    #[strum(message = "Key storage not supported for proof request")]
    BR_0158,

    #[strum(message = "Transport combination not allowed for exchange protocol")]
    BR_0159,

    #[strum(message = "No suitable transport protocol found on verifier/holder")]
    BR_0160,

    #[strum(message = "Suspension not supported for revocation method")]
    BR_0162,

    #[strum(message = "Sharing not supported to this proof schema")]
    BR_0163,

    #[strum(message = "Proof schema: claim schemas empty")]
    BR_0164,

    #[strum(message = "Validity constraint out of range")]
    BR_0166,

    #[strum(message = "Wallet unit must be in pending")]
    BR_0168,

    #[strum(message = "User Provided incorrect user code")]
    BR_0169,

    #[strum(message = "Invalid Transaction Code Use")]
    BR_0170,

    #[strum(message = "SD-JWT VC type metadata not found")]
    BR_0172,

    #[strum(
        message = "Proof of possession of issuer did for issued credential could not be verified"
    )]
    BR_0173,

    #[strum(message = "Invalid create trust anchor request")]
    BR_0177,

    #[strum(message = "Forbidden")]
    BR_0178,

    #[strum(message = "Multiple matching trust anchors")]
    BR_0179,

    #[strum(message = "Trust entity has duplicates")]
    BR_0180,

    #[strum(message = "Invalid update request")]
    BR_0181,

    #[strum(message = "Initialization error")]
    BR_0183,

    #[strum(message = "Not initialized")]
    BR_0184,

    #[strum(message = "Unable to resolve trust entity by did")]
    BR_0185,

    #[strum(message = "No trust entity found for the given did")]
    BR_0186,

    #[strum(message = "Trust anchor is disabled")]
    BR_0187,

    #[strum(message = "Trust anchor must be client")]
    BR_0188,

    #[strum(message = "JSON deserialization error")]
    BR_0189,

    #[strum(message = "Suspension not enabled for revocation method that only supports suspension")]
    BR_0191,

    #[strum(message = "Redirect uri disabled or scheme not allowed")]
    BR_0192,

    #[strum(message = "Invalid image data")]
    BR_0193,

    #[strum(message = "Empty object not allowed")]
    BR_0194,

    #[strum(message = "Empty elements in array not allowed")]
    BR_0195,

    #[strum(message = "Exchange protocol operation disabled")]
    BR_0196,

    #[strum(message = "Credential role must be Holder for revocation check")]
    BR_0197,

    #[strum(message = "Invalid proof role")]
    BR_0198,

    #[strum(message = "Invalid exchange type for retract proof")]
    BR_0199,

    #[strum(message = "Key handle error")]
    BR_0201,

    #[strum(message = "Empty value not allowed")]
    BR_0204,

    #[strum(message = "DID, Key or Certificate must be specified when creating identifier")]
    BR_0206,

    #[strum(message = "Identifier not found")]
    BR_0207,

    #[strum(message = "Certificate signature invalid")]
    BR_0211,

    #[strum(message = "Certificate revoked")]
    BR_0212,

    #[strum(message = "Certificate is expired or not yet valid")]
    BR_0213,

    #[strum(message = "Key does not match public key of certificate")]
    BR_0214,

    #[strum(message = "Overlapping did with identifier")]
    BR_0217,

    #[strum(message = "Identifier not compatible with format")]
    BR_0218,

    #[strum(message = "No key with required role available")]
    BR_0222,

    #[strum(message = "Certificate not found")]
    BR_0223,

    #[strum(message = "Certificate parsing failure")]
    BR_0224,

    #[strum(message = "Wallet storage type not supported")]
    BR_0225,

    #[strum(message = "Identifier type disabled")]
    BR_0227,

    #[strum(message = "Only didId or identifierId must be present when creating trust entity")]
    BR_0228,

    #[strum(
        message = "Type mandatory when identifierId or content is used for creating trust entity"
    )]
    BR_0229,

    #[strum(message = "Content attribute not editable for DID trust entity type")]
    BR_0230,

    #[strum(message = "Subject key identifier not matching")]
    BR_0231,

    #[strum(message = "CRL check failure")]
    BR_0233,

    #[strum(message = "CRL outdated")]
    BR_0234,

    #[strum(message = "CRL signature invalid")]
    BR_0235,

    #[strum(message = "Duplicate trust entity")]
    BR_0236,

    #[strum(message = "Rejection not supported")]
    BR_0237,

    #[strum(message = "MSO refresh not possible")]
    BR_0238,

    #[strum(message = "Identifier already exists")]
    BR_0240,

    #[strum(message = "Organisation is deactivated")]
    BR_0241,

    #[strum(message = "Certificate must be specified for identifiers of type certificate")]
    BR_0242,

    #[strum(message = "Certificate is missing authority key identifier")]
    BR_0243,

    #[strum(message = "Invalid CA trust entity certificate chain")]
    BR_0244,

    #[strum(message = "Unsupported claim data type")]
    BR_0245,

    #[strum(message = "Presentation submission must contain at least one credential")]
    BR_0246,

    #[strum(message = "Certificate already exists")]
    BR_0247,

    #[strum(message = "Unknown critical X.509 extension")]
    BR_0248,

    #[strum(message = "Certificate key usage violation")]
    BR_0249,

    #[strum(message = "Basic constraints violation")]
    BR_0250,

    #[strum(message = "Blob storage error")]
    BR_0251,

    #[strum(message = "Blob storage provider not found")]
    BR_0252,

    #[strum(message = "DID cannot be reactivated")]
    BR_0256,

    #[strum(message = "Interaction not found")]
    BR_0257,

    #[strum(message = "Minimum refresh time not reached")]
    BR_0258,

    #[strum(message = "Wallet unit not found")]
    BR_0259,

    #[strum(message = "Wallet provider not enabled in config")]
    BR_0260,

    #[strum(message = "Wallet unit revoked")]
    BR_0261,

    #[strum(message = "No wallet unit registration")]
    BR_0262,

    #[strum(message = "Cannot fetch wallet unit attestation")]
    BR_0264,

    #[strum(message = "Invalid wallet unit state")]
    BR_0265,

    #[strum(message = "App integrity validation failed")]
    BR_0266,

    #[strum(message = "Missing proof")]
    BR_0268,

    #[strum(message = "Missing public key")]
    BR_0269,

    #[strum(
        message = "App integrity check required: proof and public key must only be provided on wallet unit activation"
    )]
    BR_0270,

    #[strum(message = "Wallet unit already exists")]
    BR_0271,

    #[strum(message = "Engagement provided for non ISO mDL flow")]
    BR_0272,

    #[strum(message = "NFC adapter not enabled")]
    BR_0273,

    #[strum(message = "NFC not supported")]
    BR_0274,

    #[strum(message = "Another NFC operation running")]
    BR_0275,

    #[strum(message = "NFC operation not running")]
    BR_0276,

    #[strum(message = "NFC operation cancelled")]
    BR_0277,

    #[strum(message = "NFC session closed")]
    BR_0278,

    #[strum(message = "App integrity check not required: provide proof and public key")]
    BR_0279,

    #[strum(message = "App integrity check required")]
    BR_0280,

    #[strum(message = "App integrity check not required")]
    BR_0281,

    #[strum(message = "Wallet provider already associated")]
    BR_0283,

    #[strum(message = "Wallet provider not configured")]
    BR_0284,

    #[strum(message = "Identifier does not belong to this organisation")]
    BR_0285,

    #[strum(message = "Wallet provider not associated with any organisation")]
    BR_0286,

    #[strum(message = "Organisation not specified")]
    BR_0290,

    #[strum(message = "Invalid presentation submission")]
    BR_0291,

    #[strum(message = "Verification protocol is incompatible with this endpoint version")]
    BR_0292,
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
            Self::IssuanceProtocolError(error) => error.error_code(),
            Self::VerificationProtocolError(error) => error.error_code(),
            Self::CryptoError(_) => ErrorCode::BR_0050,
            Self::FormatterError(error) => error.error_code(),
            Self::KeyStorageError(_) | Self::KeyStorageProvider(_) => ErrorCode::BR_0039,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::OpenID4VCError(_) | Self::OpenID4VCIError(_) | Self::OpenIDIssuanceError(_) => {
                ErrorCode::BR_0048
            }
            Self::ConfigValidationError(error) => error.error_code(),
            Self::BitstringError(_) => ErrorCode::BR_0049,
            Self::MissingSigner(_) => ErrorCode::BR_0060,
            Self::MissingAlgorithm(_) => ErrorCode::BR_0061,
            Self::MissingExchangeProtocol(_) => ErrorCode::BR_0046,
            Self::KeyAlgorithmError(_) => ErrorCode::BR_0063,
            Self::KeyAlgorithmProviderError(_) => ErrorCode::BR_0063,
            Self::DidMethodError(_) => ErrorCode::BR_0064,
            Self::DidMethodProviderError(error) => error.error_code(),
            Self::ValidationError(_) | Self::Other(_) => ErrorCode::BR_0000,
            Self::Revocation(_) => ErrorCode::BR_0101,
            Self::TrustManagementError(_) => ErrorCode::BR_0185,
            Self::KeyHandleError(_) => ErrorCode::BR_0201,
            Self::BlobStorageError(_) => ErrorCode::BR_0251,
            Self::WalletProviderError(error) => error.error_code(),
            Self::WalletUnitAttestationError(error) => error.error_code(),
            Self::NfcError(error) => error.error_code(),
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
            | Self::DatatypeValidation(_)
            | Self::DuplicateUrlScheme { .. }
            | Self::MultipleFallbackProviders { .. }
            | Self::MissingX509CaCertificate => ErrorCode::BR_0051,
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
            Self::TrustEntity(_) | Self::TrustEntityByEntityKey(_) => ErrorCode::BR_0121,
            Self::SdJwtVcTypeMetadata(_) => ErrorCode::BR_0172,
            Self::Identifier(_) | Self::IdentifierByDidId(_) => ErrorCode::BR_0207,
            Self::Certificate(_) => ErrorCode::BR_0223,
            Self::Interaction(_) => ErrorCode::BR_0257,
            Self::WalletUnit(_) => ErrorCode::BR_0259,
            Self::WalletUnitAttestationByOrganisation(_) => ErrorCode::BR_0262,
        }
    }
}

impl ErrorCodeMixin for BusinessLogicError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::OrganisationAlreadyExists => ErrorCode::BR_0023,
            Self::OrganisationIsDeactivated(_) => ErrorCode::BR_0241,
            Self::IncompatibleDidType { .. } => ErrorCode::BR_0025,
            Self::IncompatibleIdentifierType { .. } => ErrorCode::BR_0025,
            Self::DidMethodIncapableKeyAlgorithm { .. } => ErrorCode::BR_0065,
            Self::InvalidDidMethod { .. } => ErrorCode::BR_0026,
            Self::DidIsDeactivated(_) => ErrorCode::BR_0027,
            Self::IdentifierIsDeactivated(_) => ErrorCode::BR_0027,
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
            Self::SuspensionNotEnabledForSuspendOnlyRevocationMethod => ErrorCode::BR_0191,
            Self::RevocationCheckNotAllowedForRole { .. } => ErrorCode::BR_0197,
            Self::InvalidProofRole { .. } => ErrorCode::BR_0198,
            Self::InvalidProofExchangeForRetraction { .. } => ErrorCode::BR_0199,
            Self::OverlappingHolderDidWithIdentifier => ErrorCode::BR_0217,
            Self::IncompatibleIssuanceIdentifier => ErrorCode::BR_0218,
            Self::IncompatibleProofVerificationIdentifier => ErrorCode::BR_0218,
            Self::IncompatibleHolderDidMethod => ErrorCode::BR_0218,
            Self::IncompatibleHolderIdentifier => ErrorCode::BR_0218,
            Self::IncompatibleHolderKeyAlgorithm => ErrorCode::BR_0218,
            Self::IdentifierTypeNotFound => ErrorCode::BR_0207,
            Self::RejectionNotSupported => ErrorCode::BR_0237,
            Self::IdentifierAlreadyExists => ErrorCode::BR_0240,
            Self::IdentifierCertificateIdMismatch { .. } | Self::CertificateIdNotSpecified => {
                ErrorCode::BR_0242
            }
            Self::EmptyPresentationSubmission => ErrorCode::BR_0246,
            Self::CertificateAlreadyExists => ErrorCode::BR_0247,
            Self::IdentifierOrganisationMismatch => ErrorCode::BR_0285,
            Self::WalletProviderAlreadyAssociated(_) => ErrorCode::BR_0283,
            Self::OrganisationNotSpecified => ErrorCode::BR_0290,
            Self::InvalidPresentationSubmission { .. } => ErrorCode::BR_0291,
            Self::IncompatiblePresentationEndpoint => ErrorCode::BR_0292,
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
            Self::Forbidden => ErrorCode::BR_0178,
            Self::InvalidUpdateRequest => ErrorCode::BR_0181,
            Self::DeserializationError(_) => ErrorCode::BR_0189,
            Self::InvalidRedirectUri => ErrorCode::BR_0192,
            Self::InvalidExchangeOperation { .. } => ErrorCode::BR_0196,
            Self::EmptyObjectNotAllowed => ErrorCode::BR_0194,
            Self::EmptyArrayValueNotAllowed => ErrorCode::BR_0195,
            Self::InvalidImage(_) => ErrorCode::BR_0193,
            Self::EmptyValueNotAllowed => ErrorCode::BR_0204,
            Self::NoKeyWithRole(_) => ErrorCode::BR_0222,
            Self::InvalidIdentifierInput => ErrorCode::BR_0206,
            Self::CertificateSignatureInvalid => ErrorCode::BR_0211,
            Self::CertificateRevoked => ErrorCode::BR_0212,
            Self::CertificateExpired | Self::CertificateNotYetValid => ErrorCode::BR_0213,
            Self::CertificateKeyNotMatching => ErrorCode::BR_0214,
            Self::CertificateParsingFailed(_) => ErrorCode::BR_0224,
            Self::UnknownCriticalExtension(_) => ErrorCode::BR_0248,
            Self::KeyUsageViolation(_) => ErrorCode::BR_0249,
            Self::IdentifierTypeDisabled(_) => ErrorCode::BR_0227,
            Self::TrustEntityAmbiguousIds => ErrorCode::BR_0228,
            Self::TrustEntityTypeNotSpecified => ErrorCode::BR_0229,
            Self::TrustEntityTypeInvalid => ErrorCode::BR_0230,
            Self::TrustEntitySubjectKeyIdentifierDoesNotMatch => ErrorCode::BR_0231,
            Self::CRLCheckFailed(_) => ErrorCode::BR_0233,
            Self::CRLOutdated => ErrorCode::BR_0234,
            Self::CRLSignatureInvalid => ErrorCode::BR_0235,
            Self::WalletStorageTypeDisabled(_) => ErrorCode::BR_0225,
            Self::MissingAuthorityKeyIdentifier => ErrorCode::BR_0243,
            Self::InvalidCaCertificateChain(_) => ErrorCode::BR_0244,
            Self::CredentialSchemaClaimSchemaUnsupportedDatatype { .. } => ErrorCode::BR_0245,
            Self::KeyMustNotBeRemote(_) => ErrorCode::BR_0076,
            Self::BasicConstraintsViolation(_) => ErrorCode::BR_0250,
            Self::MissingVerificationEngagementConfig(_) => ErrorCode::BR_0077,
            Self::MissingEngagementForISOmDLFlow => ErrorCode::BR_0079,
            Self::InvalidProofEngagement => ErrorCode::BR_0078,
            Self::EngagementProvidedForNonISOmDLFlow => ErrorCode::BR_0272,
        }
    }
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
            Self::Suspended | Self::RefreshTooSoon => ErrorCode::BR_0238,
        }
    }
}

impl ErrorCodeMixin for VerificationProtocolError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Failed(_) => ErrorCode::BR_0062,
            Self::Transport(_) => ErrorCode::BR_0086,
            Self::JsonError(_) => ErrorCode::BR_0062,
            Self::OperationNotSupported => ErrorCode::BR_0062,
            Self::InvalidRequest(_) => ErrorCode::BR_0085,
            Self::Disabled(_) => ErrorCode::BR_0085,
            Self::Other(_) => ErrorCode::BR_0062,
            Self::StorageAccessError(_) => ErrorCode::BR_0062,
            Self::InvalidDcqlQueryOrPresentationDefinition(_) => ErrorCode::BR_0083,
            Self::DcqlError(_) => ErrorCode::BR_0085,
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
            | Self::DidValueValidationError
            | Self::Other(_) => ErrorCode::BR_0064,
            Self::MissingProvider(_) => ErrorCode::BR_0031,
        }
    }
}

impl ErrorCodeMixin for DataLayerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Db(_) => ErrorCode::BR_0054,
            Self::AlreadyExists
            | Self::IncorrectParameters
            | Self::RecordNotUpdated
            | Self::MappingError
            | Self::IncompleteClaimsList { .. }
            | Self::IncompleteClaimsSchemaList { .. }
            | Self::MissingProofState { .. }
            | Self::MissingRequiredRelation { .. }
            | Self::MissingClaimsSchemaForClaim(_, _)
            | Self::TransactionError(_) => ErrorCode::BR_0000,
        }
    }
}

impl ErrorCodeMixin for MissingProviderError {
    fn error_code(&self) -> ErrorCode {
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
            Self::BlobStorage(_) => ErrorCode::BR_0252,
        }
    }
}

impl ErrorCodeMixin for WalletProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::WalletProviderDisabled(_) => ErrorCode::BR_0260,
            Self::CouldNotVerifyProof(_) => ErrorCode::BR_0071,
            Self::IssuerKeyWithAlgorithmNotFound(_) => ErrorCode::BR_0222,
            Self::WalletUnitRevoked => ErrorCode::BR_0261,
            Self::RefreshTimeNotReached => ErrorCode::BR_0258,
            Self::MissingWalletUnitAttestationNonce | Self::InvalidWalletUnitAttestationNonce => {
                ErrorCode::BR_0153
            }
            Self::InvalidWalletUnitState => ErrorCode::BR_0265,
            Self::AppIntegrityValidationError(_) => ErrorCode::BR_0266,
            Self::MissingProof => ErrorCode::BR_0268,
            Self::MissingPublicKey => ErrorCode::BR_0269,
            Self::AppIntegrityCheckRequired => ErrorCode::BR_0270,
            Self::WalletUnitAlreadyExists => ErrorCode::BR_0271,
            Self::AppIntegrityCheckNotRequired => ErrorCode::BR_0279,
            Self::WalletProviderNotConfigured | Self::WalletProviderOrganisationDisabled => {
                ErrorCode::BR_0284
            }
            Self::WalletProviderNotAssociatedWithOrganisation => ErrorCode::BR_0286,
            Self::WalletUnitMustBeActive => ErrorCode::BR_0081,
            Self::WalletUnitMustBePending => ErrorCode::BR_0168,
        }
    }
}

impl ErrorCodeMixin for WalletUnitAttestationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            WalletUnitAttestationError::WalletUnitRevoked => ErrorCode::BR_0261,
            WalletUnitAttestationError::WalletProviderClientFailure(_) => ErrorCode::BR_0264,
            WalletUnitAttestationError::AppIntegrityCheckRequired => ErrorCode::BR_0280,
            WalletUnitAttestationError::AppIntegrityCheckNotRequired => ErrorCode::BR_0281,
        }
    }
}
