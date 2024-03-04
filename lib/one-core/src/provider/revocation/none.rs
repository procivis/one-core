use shared_types::DidValue;

use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::revocation::RevocationMethod;
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
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        Ok(None)
    }

    async fn mark_credential_revoked(&self, _credential: &Credential) -> Result<(), ServiceError> {
        Err(ServiceError::ValidationError(
            "Credential cannot be revoked".to_string(),
        ))
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_did: &DidValue,
    ) -> Result<bool, ServiceError> {
        Err(ServiceError::ValidationError(
            "Credential cannot be revoked - status invalid".to_string(),
        ))
    }
}
