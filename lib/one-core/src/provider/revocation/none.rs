use one_providers::common_models::credential::OpenCredential;
use one_providers::common_models::did::DidValue;
use one_providers::credential_formatter::model::CredentialStatus;
use one_providers::revocation::error::RevocationError;
use one_providers::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationState, JsonLdContext,
    RevocationMethodCapabilities, RevocationUpdate,
};
use one_providers::revocation::RevocationMethod;

pub struct NoneRevocation {}

#[async_trait::async_trait]
impl RevocationMethod for NoneRevocation {
    fn get_status_type(&self) -> String {
        "NONE".to_string()
    }

    async fn add_issued_credential(
        &self,
        _credential: &OpenCredential,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<
        (
            Option<RevocationUpdate>,
            Vec<one_providers::revocation::model::CredentialRevocationInfo>,
        ),
        RevocationError,
    > {
        Ok((None, vec![]))
    }

    async fn mark_credential_as(
        &self,
        _credential: &OpenCredential,
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
