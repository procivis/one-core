use shared_types::DidValue;
use strum::Display;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::certificate::Certificate;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
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
    #[error(
        "Chain or self-signed must be specified when creating Certificate Authority identifier"
    )]
    InvalidCertificateAuthorityIdentifierInput,
    #[error("Key does not match public key of certificate")]
    CertificateKeyNotMatching,

    #[error("DID method error: `{0}`")]
    DidMethodError(#[from] DidMethodError),
    #[error("Key algorithm provider error: `{0}`")]
    KeyAlgorithmProviderError(#[from] KeyAlgorithmProviderError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0000,
            Self::CertificateAlreadyExists => ErrorCode::BR_0247,
            Self::IdentifierAlreadyExists => ErrorCode::BR_0240,
            Self::DidMethodIncapableKeyAlgorithm { .. } => ErrorCode::BR_0065,
            Self::DidValueAlreadyExists(_) => ErrorCode::BR_0028,
            Self::KeyMustNotBeRemote(_) => ErrorCode::BR_0076,
            Self::InvalidCertificateAuthorityIdentifierInput => ErrorCode::BR_0331,
            Self::CertificateKeyNotMatching => ErrorCode::BR_0214,
            Self::DidMethodError(_) => ErrorCode::BR_0064,
            Self::KeyAlgorithmProviderError(_) => ErrorCode::BR_0063,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
