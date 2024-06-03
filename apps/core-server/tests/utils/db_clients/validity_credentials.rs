use std::sync::Arc;

use one_core::model::validity_credential::{Lvvc, ValidityCredential, ValidityCredentialType};
use one_core::repository::validity_credential_repository::ValidityCredentialRepository;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct ValidityCredentialsDB {
    repository: Arc<dyn ValidityCredentialRepository>,
}

impl ValidityCredentialsDB {
    pub fn new(repository: Arc<dyn ValidityCredentialRepository>) -> Self {
        Self { repository }
    }

    pub async fn create_lvvc(
        &self,
        id: Option<Uuid>,
        credential: Vec<u8>,
        credential_id: CredentialId,
    ) -> Lvvc {
        let lvvc = Lvvc {
            id: id.unwrap_or_else(Uuid::new_v4),
            created_date: OffsetDateTime::now_utc(),
            credential,
            linked_credential_id: credential_id,
        };

        self.repository.insert(lvvc.clone().into()).await.unwrap();

        lvvc
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
