use std::sync::Arc;

use one_core::model::validity_credential::{ValidityCredential, ValidityCredentialType};
use one_core::repository::validity_credential_repository::ValidityCredentialRepository;
use shared_types::CredentialId;

pub struct ValidityCredentialsDB {
    repository: Arc<dyn ValidityCredentialRepository>,
}

impl ValidityCredentialsDB {
    pub fn new(repository: Arc<dyn ValidityCredentialRepository>) -> Self {
        Self { repository }
    }

    pub async fn get_all_by_credential_id(
        &self,
        credential_id: CredentialId,
        credential_type: ValidityCredentialType,
    ) -> Vec<ValidityCredential> {
        self.repository
            .get_all_by_credential_id(credential_id, credential_type)
            .await
            .unwrap()
    }
}
