use crate::model::credential::Credential;
use crate::revocation::RevocationMethod;
use crate::service::error::ServiceError;

use super::CredentialRevocationInfo;

pub struct NoneRevocation {}

#[async_trait::async_trait]
impl RevocationMethod for NoneRevocation {
    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        Ok(None)
    }

    async fn mark_credential_revoked(&self, _credential: &Credential) -> Result<(), ServiceError> {
        Err(ServiceError::ValidationError(
            "Credential cannot be revoked".to_string(),
        ))
    }
}
