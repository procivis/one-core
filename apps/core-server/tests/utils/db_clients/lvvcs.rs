use std::sync::Arc;

use one_core::model::lvvc::Lvvc;
use one_core::repository::lvvc_repository::LvvcRepository;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct LvvcsDB {
    repository: Arc<dyn LvvcRepository>,
}

impl LvvcsDB {
    pub fn new(repository: Arc<dyn LvvcRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
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

        self.repository.insert(lvvc.to_owned()).await.unwrap();

        lvvc
    }

    pub async fn get_all_by_credential_id(&self, credential_id: CredentialId) -> Vec<Lvvc> {
        self.repository
            .get_all_by_credential_id(credential_id)
            .await
            .unwrap()
    }
}
