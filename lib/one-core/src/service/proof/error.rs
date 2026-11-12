use shared_types::{CredentialSchemaId, DidId, ProofSchemaId, TransactionDataId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::did::KeyRole;
use crate::model::identifier::IdentifierType;
use crate::model::proof::{ProofRole, ProofStateEnum};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;

#[derive(thiserror::Error, Debug)]
pub enum ProofServiceError {
    #[error("Invalid proof state: {0}")]
    InvalidState(ProofStateEnum),
    #[error("Invalid proof role: {0}")]
    InvalidRole(ProofRole),

    #[error("No verifier specified")]
    NoVerifier,
    #[error("Invalid identifier type: `{0}`")]
    InvalidIdentifierType(IdentifierType),
    #[error("Verifier identifier does not belong to the organisation of the proof schema")]
    IdentifierOrganisationMismatch,
    #[error("Engagement provided for non ISO mDL flow")]
    EngagementProvidedForNonISOmDLFlow,
    #[error("Missing engagement for ISO mDL flow")]
    MissingEngagementForISOmDLFlow,
    #[error("Invalid mdl parameters")]
    InvalidMdlParameters,
    #[error("Missing configuration for verification engagement type: {0}")]
    MissingVerificationEngagementConfig(String),
    #[error("Invalid value of proof engagement")]
    InvalidEngagement,
    #[error("Incompatible proof verfication key storage")]
    IncompatibleKeyStorage,
    #[error("Notifications not allowed for protocol: `{protocol}`")]
    NotificationsNotAllowed { protocol: String },
    #[error("Redirect uri disabled or scheme not allowed")]
    InvalidRedirectUri,
    #[error("Incompatible proof exchange protocol")]
    IncompatibleExchangeProtocol,
    #[error("Incompatible proof verification identifier")]
    IncompatibleVerificationIdentifier,
    #[error("Missing key with role `{0}`")]
    NoKeyWithRole(KeyRole),
    #[error("Invalid exchange type {value}: {source}")]
    InvalidExchangeType {
        value: String,
        source: anyhow::Error,
    },
    #[error("Missing proof schema: `{0}`")]
    MissingProofSchema(ProofSchemaId),
    #[error("Proof schema `{0}` is deleted")]
    ProofSchemaDeleted(ProofSchemaId),
    #[error("Did `{0}` not found")]
    MissingDid(DidId),
    #[error("BBS not supported")]
    BBSNotSupported,

    #[error("Duplicit transaction data")]
    DuplicitTransactionData,
    #[error("Credential schema `{0}` format does not support transaction data")]
    TransactionDataFormatUnsupported(CredentialSchemaId),
    #[error("Transaction data references credential schema `{0}` not part of the proof schema")]
    TransactionDataUnknownCredentialSchema(CredentialSchemaId),
    #[error("Transaction data `{0}` not found")]
    TransactionDataNotFound(TransactionDataId),
    #[error("Transaction data entries cannot each be authorized by a distinct credential")]
    UnsatisfiableTransactionData,
    #[error("No ecosystem selected")]
    NoEcosystemSelected,

    #[error("Proof error: `{0}`")]
    Other(String),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("OpenID4VC error: `{0}`")]
    OpenID4VCError(#[from] OpenID4VCError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for ProofServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidState(_) => ErrorCode::BR_0013,
            Self::InvalidRole(_) => ErrorCode::BR_0198,
            Self::NoVerifier | Self::InvalidIdentifierType(_) => ErrorCode::BR_0323,
            Self::IdentifierOrganisationMismatch => ErrorCode::BR_0285,
            Self::MissingEngagementForISOmDLFlow => ErrorCode::BR_0079,
            Self::EngagementProvidedForNonISOmDLFlow => ErrorCode::BR_0272,
            Self::InvalidMdlParameters => ErrorCode::BR_0147,
            Self::MissingVerificationEngagementConfig(_) => ErrorCode::BR_0077,
            Self::InvalidEngagement => ErrorCode::BR_0078,
            Self::IncompatibleKeyStorage => ErrorCode::BR_0158,
            Self::InvalidRedirectUri => ErrorCode::BR_0192,
            Self::IncompatibleExchangeProtocol => ErrorCode::BR_0112,
            Self::IncompatibleVerificationIdentifier => ErrorCode::BR_0218,
            Self::NotificationsNotAllowed { .. } => ErrorCode::BR_0372,
            Self::NoKeyWithRole(_) => ErrorCode::BR_0222,
            Self::BBSNotSupported => ErrorCode::BR_0091,
            Self::InvalidExchangeType { .. } => ErrorCode::BR_0052,
            Self::ProofSchemaDeleted(_) => ErrorCode::BR_0019,
            Self::MissingProofSchema(_) => ErrorCode::BR_0020,
            Self::MissingDid(_) => ErrorCode::BR_0024,
            Self::DuplicitTransactionData => ErrorCode::BR_0458,
            Self::TransactionDataFormatUnsupported(_) => ErrorCode::BR_0460,
            Self::TransactionDataUnknownCredentialSchema(_) => ErrorCode::BR_0461,
            Self::TransactionDataNotFound(_) => ErrorCode::BR_0462,
            Self::UnsatisfiableTransactionData => ErrorCode::BR_0463,
            Self::NoEcosystemSelected => ErrorCode::BR_0476,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Other(_) => ErrorCode::BR_0000,
            Self::OpenID4VCError(_) => ErrorCode::BR_0048,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
