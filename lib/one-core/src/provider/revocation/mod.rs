use serde::Serialize;
use shared_types::DidValue;

use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::service::error::ServiceError;

pub mod bitstring_status_list;
pub mod lvvc;
pub mod none;
pub mod provider;
pub mod status_list_2021;

#[derive(Clone, Default, Serialize)]
pub struct RevocationMethodCapabilities {
    pub operations: Vec<String>,
}

pub struct CredentialRevocationInfo {
    pub credential_status: CredentialStatus,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait RevocationMethod: Send + Sync {
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
        issuer_did: &DidValue,
    ) -> Result<bool, ServiceError>;

    fn get_capabilities(&self) -> RevocationMethodCapabilities;
}
