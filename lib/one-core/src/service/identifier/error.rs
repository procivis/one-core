use shared_types::{
    BlobId, CredentialSchemaId, IdentifierId, OrganisationId, ProofSchemaId, TrustListSubscriberId,
};

use crate::config::core_config::IdentifierType;
use crate::error::{ErrorCode, ErrorCodeMixin, ErrorData, NestedError};
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::identifier::IdentifierType as IdentifierDataType;

#[derive(thiserror::Error, Debug)]
pub enum IdentifierServiceError {
    #[error("Identifier `{0}` not found")]
    NotFound(IdentifierId),
    #[error("Identifier type `{0}` disabled")]
    IdentifierTypeDisabled(IdentifierType),
    #[error(
        "DID, Key, Certificate or Certificate Authority must be specified when creating identifier"
    )]
    InvalidCreationInput,
    #[error("Remote identifier `{0}` already exists")]
    RemoteIdentifierAlreadyExists(IdentifierId),

    #[error("Organisation `{0}` is deactivated")]
    OrganisationDeactivated(OrganisationId),
    #[error("Trust information blob `{0}` not found")]
    MissingTrustInformationBlob(BlobId),
    #[error("Logo blob `{0}` not found")]
    MissingLogoBlob(BlobId),
    #[error("Invalid trust information: {0}")]
    InvalidTrustInformation(String),
    #[error("No ecosystem enabled to validate trust information")]
    NoEcosystemEnabledForTrustInformation,
    #[error("Trust information rejected by all enabled ecosystems")]
    TrustInformationRejected(EcosystemOutcomes),

    #[error("Missing trust list subscriber `{0}`")]
    MissingTrustListSubscriber(TrustListSubscriberId),
    #[error("Credential schema `{0}` not found")]
    CredentialSchemaNotFound(CredentialSchemaId),
    #[error("Proof schema `{0}` not found")]
    ProofSchemaNotFound(ProofSchemaId),
    #[error("Invalid ecosystem query: {0}")]
    InvalidEcosystemQuery(String),
    #[error("DID keys of identifier `{0}` cannot be updated: {1}")]
    DidKeysNotUpdatable(IdentifierId, String),

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("Attribute `{attribute}` cannot be updated for identifier type `{identifier_type}`")]
    InvalidUpdateForIdentifierType {
        identifier_type: IdentifierDataType,
        attribute: &'static str,
    },
    #[error("Key must not be remote: `{0}`")]
    KeyMustNotBeRemote(String),
    #[error("Key does not belong to this organisation")]
    KeyOrganisationMismatch,
    #[error("Operation requires a CERTIFICATE or CA identifier")]
    InvalidIdentifierTypeForCertificateOperation,
    #[error("Identifier must keep at least one certificate")]
    CannotRemoveLastCertificate,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for IdentifierServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0207,
            Self::IdentifierTypeDisabled(_) => ErrorCode::BR_0227,
            Self::InvalidCreationInput => ErrorCode::BR_0206,
            Self::RemoteIdentifierAlreadyExists(_) => ErrorCode::BR_0240,
            Self::OrganisationDeactivated(_) => ErrorCode::BR_0241,
            Self::CredentialSchemaNotFound(_) => ErrorCode::BR_0413,
            Self::ProofSchemaNotFound(_) => ErrorCode::BR_0414,
            Self::MissingTrustListSubscriber(_) => ErrorCode::BR_0388,
            Self::MissingTrustInformationBlob(_) => ErrorCode::BR_0415,
            Self::InvalidTrustInformation(_)
            | Self::NoEcosystemEnabledForTrustInformation
            | Self::TrustInformationRejected(_) => ErrorCode::BR_0416,
            Self::InvalidEcosystemQuery(_) => ErrorCode::BR_0479,
            Self::DidKeysNotUpdatable(_, _) => ErrorCode::BR_0181,
            Self::MissingLogoBlob(_) => ErrorCode::BR_0484,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::InvalidUpdateForIdentifierType { .. } => ErrorCode::BR_0513,
            Self::KeyMustNotBeRemote(_) => ErrorCode::BR_0076,
            Self::KeyOrganisationMismatch => ErrorCode::BR_0285,
            Self::InvalidIdentifierTypeForCertificateOperation => ErrorCode::BR_0514,
            Self::CannotRemoveLastCertificate => ErrorCode::BR_0515,
            Self::Nested(nested) => nested.error_code(),
        }
    }

    fn error_data(&self) -> Option<ErrorData> {
        match self {
            Self::TrustInformationRejected(outcomes) => {
                Some(ErrorData::EcosystemsResolved(outcomes.to_owned()))
            }
            Self::Nested(nested) => nested.error_data(),
            _ => None,
        }
    }
}
