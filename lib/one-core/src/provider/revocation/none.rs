use one_providers::credential_formatter::model::CredentialStatus;
use shared_types::DidValue;

use crate::model::credential::Credential;
use crate::provider::revocation::{
    CredentialDataByRole, CredentialRevocationState, JsonLdContext, RevocationMethod,
};
use crate::service::error::ServiceError;

use super::{CredentialRevocationInfo, RevocationMethodCapabilities};

pub struct NoneRevocation {}

#[async_trait::async_trait]
impl RevocationMethod for NoneRevocation {
    fn get_status_type(&self) -> String {
        "NONE".to_string()
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities { operations: vec![] }
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, ServiceError> {
        Ok(vec![])
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, ServiceError> {
        Err(ServiceError::ValidationError(
            "Credential cannot be revoked - status invalid".to_string(),
        ))
    }

    async fn mark_credential_as(
        &self,
        _credential: &Credential,
        _new_state: CredentialRevocationState,
    ) -> Result<(), ServiceError> {
        Err(ServiceError::ValidationError(
            "Credential cannot be revoked, reactivated or suspended".to_string(),
        ))
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, ServiceError> {
        Ok(JsonLdContext::default())
    }
}
