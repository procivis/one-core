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

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait RevocationMethod {
    fn get_status_type(&self) -> String;

    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError>;

    async fn mark_credential_revoked(&self, credential: &Credential) -> Result<(), ServiceError>;

    /// perform check of credential revocation status
    /// * returns `bool` - true if credential revoked, false if valid
    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &str,
    ) -> Result<bool, ServiceError>;
}
