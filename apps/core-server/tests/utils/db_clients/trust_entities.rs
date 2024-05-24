use std::sync::Arc;

use one_core::{
    model::trust_entity::{TrustEntity, TrustEntityRole},
    repository::trust_entity_repository::TrustEntityRepository,
};
use shared_types::{TrustAnchorId, TrustEntityId};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct TrustEntityDB {
    repository: Arc<dyn TrustEntityRepository>,
}

impl TrustEntityDB {
    pub fn new(repository: Arc<dyn TrustEntityRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        entity_id: &str,
        name: &str,
        role: TrustEntityRole,
        trust_anchor_id: TrustAnchorId,
    ) -> TrustEntity {
        let trust_anchor = TrustEntity {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            entity_id: entity_id.into(),
            name: name.into(),
            logo: None,
            website: None,
            terms_url: None,
            privacy_url: None,
            role,
            trust_anchor_id,
        };

        self.repository.create(trust_anchor.clone()).await.unwrap();

        trust_anchor
    }

    pub async fn get(&self, id: TrustEntityId) -> Option<TrustEntity> {
        self.repository.get(id).await.unwrap()
    }
}
