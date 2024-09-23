use shared_types::DidValue;

use super::model::CredentialRevocationInfo;
use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationState, JsonLdContext,
    RevocationMethodCapabilities, RevocationUpdate,
};
use crate::provider::revocation::RevocationMethod;

pub struct NoneRevocation {}

#[async_trait::async_trait]
impl RevocationMethod for NoneRevocation {
    fn get_status_type(&self) -> String {
        "NONE".to_string()
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError> {
        Ok((None, vec![]))
    }

    async fn mark_credential_as(
        &self,
        _credential: &Credential,
        _new_state: CredentialRevocationState,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError> {
        Err(RevocationError::ValidationError(
            "Credential cannot be revoked, reactivated or suspended".to_string(),
        ))
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, RevocationError> {
        Err(RevocationError::ValidationError(
            "Credential cannot be revoked - status invalid".to_string(),
        ))
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities { operations: vec![] }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }

    fn get_params(&self) -> Result<serde_json::Value, RevocationError> {
        Ok(serde_json::json!({}))
    }
}
