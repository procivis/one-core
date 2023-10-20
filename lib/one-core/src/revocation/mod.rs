use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::service::error::ServiceError;

pub mod none;
pub mod provider;
pub mod status_list_2021;

pub struct CredentialRevocationInfo {
    pub additional_vc_contexts: Vec<String>,
    pub credential_status: CredentialStatus,
}

#[async_trait::async_trait]
pub trait RevocationMethod {
    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError>;

    async fn mark_credential_revoked(&self, credential: &Credential) -> Result<(), ServiceError>;
}

#[cfg(any(test, feature = "mock"))]
pub mod mock;
