use strum::Display;

use crate::model::certificate::Certificate;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::service::certificate::dto::CreateCertificateRequestDTO;
use crate::service::did::dto::CreateDidRequestDTO;
use crate::service::error::ServiceError;
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
    ) -> Result<(Identifier, RemoteIdentifierRelation), ServiceError>;

    async fn create_local_identifier(
        &self,
        name: String,
        request: CreateLocalIdentifierRequest,
        organisation: Organisation,
    ) -> Result<Identifier, ServiceError>;
}
