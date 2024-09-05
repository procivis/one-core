use shared_types::CredentialId;

use super::error::DataLayerError;
use crate::model::validity_credential::{ValidityCredential, ValidityCredentialType};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ValidityCredentialRepository: Send + Sync + 'static {
    async fn insert(&self, credential: ValidityCredential) -> Result<(), DataLayerError>;

    async fn get_latest_by_credential_id(
        &self,
        credential_id: CredentialId,
        credential_type: ValidityCredentialType,
    ) -> Result<Option<ValidityCredential>, DataLayerError>;

    async fn get_all_by_credential_id(
        &self,
        credential_id: CredentialId,
        credential_type: ValidityCredentialType,
    ) -> Result<Vec<ValidityCredential>, DataLayerError>;
}
