use shared_types::{DidValue, IdentifierId, KeyId};
use strum::Display;

use crate::config::core_config::SignerType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::certificate::Certificate;
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::service::certificate::dto::CreateCertificateRequestDTO;
use crate::service::did::dto::CreateDidRequestDTO;
use crate::service::identifier::dto::CreateCertificateAuthorityRequestDTO;

pub(crate) mod creator;
mod local;
mod remote;

#[cfg(test)]
mod test;

#[derive(Debug, Display, PartialEq)]
pub(crate) enum IdentifierRole {
    #[strum(to_string = "holder")]
    Holder,
    #[strum(to_string = "issuer")]
    Issuer,
    #[strum(to_string = "verifier")]
    Verifier,
}

#[derive(Debug, PartialEq)]
pub(crate) enum RemoteIdentifierRelation {
    Did(Did),
    Certificate(Certificate),
    Key(Key),
}

#[derive(Debug)]
pub(crate) enum CreateLocalIdentifierRequest {
    Did(CreateDidRequestDTO),
    Key(Key),
    Certificate(Vec<CreateCertificateRequestDTO>),
    CertificateAuthority(Vec<CreateCertificateAuthorityRequestDTO>),
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait IdentifierCreator: Send + Sync {
    async fn get_or_create_remote_identifier(
        &self,
        organisation: &Option<Organisation>,
        details: &IdentifierDetails,
        role: IdentifierRole,
    ) -> Result<(Identifier, RemoteIdentifierRelation), Error>;

    async fn create_local_identifier(
        &self,
        name: String,
        request: CreateLocalIdentifierRequest,
        organisation: Organisation,
    ) -> Result<Identifier, Error>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[expect(clippy::enum_variant_names)]
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("Certificate already exists")]
    CertificateAlreadyExists,
    #[error("Identifier already exists")]
    IdentifierAlreadyExists,
    #[error("Incapable DID method: {key_algorithm}")]
    DidMethodIncapableKeyAlgorithm { key_algorithm: String },
    #[error("Did value already exists: {0}")]
    DidValueAlreadyExists(DidValue),
    #[error("Key must not be remote: `{0}`")]
    KeyMustNotBeRemote(String),
    #[error("Chain or content must be specified when creating Certificate")]
    InvalidCertificateInput,
    #[error("Key does not match public key of certificate")]
    CertificateKeyNotMatching,
    #[error("Certificate missing common name")]
    MissingCertificateCommonName,
    #[error("Invalid signer type: `{0}`")]
    InvalidSignerType(SignerType),
    #[error("Invalid key algorithm: {0}")]
    InvalidKeyAlgorithm(String),
    #[error("Key `{0}` not found")]
    KeyNotFound(KeyId),
    #[error("Identifier `{0}` not found")]
    IdentifierNotFound(IdentifierId),
    #[error("Identifier type `{0}` not supported")]
    InvalidIdentifierType(IdentifierType),
    #[error("Identifier does not belong to this organisation")]
    OrganisationMismatch,
    #[error("Invalid CSR profile")]
    InvalidCSRProfile,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::CertificateAlreadyExists => ErrorCode::BR_0247,
            Self::IdentifierAlreadyExists => ErrorCode::BR_0240,
            Self::DidMethodIncapableKeyAlgorithm { .. } => ErrorCode::BR_0065,
            Self::DidValueAlreadyExists(_) => ErrorCode::BR_0028,
            Self::KeyMustNotBeRemote(_) => ErrorCode::BR_0076,
            Self::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            Self::InvalidCertificateInput => ErrorCode::BR_0331,
            Self::InvalidSignerType(_) => ErrorCode::BR_0381,
            Self::CertificateKeyNotMatching => ErrorCode::BR_0214,
            Self::MissingCertificateCommonName => ErrorCode::BR_0224,
            Self::KeyNotFound(_) => ErrorCode::BR_0037,
            Self::IdentifierNotFound(_) => ErrorCode::BR_0207,
            Self::InvalidIdentifierType(_) => ErrorCode::BR_0330,
            Self::OrganisationMismatch => ErrorCode::BR_0285,
            Self::InvalidCSRProfile => ErrorCode::BR_0323,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
