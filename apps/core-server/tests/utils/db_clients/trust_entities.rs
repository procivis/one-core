use std::sync::Arc;

use one_core::model::did::Did;
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use one_core::model::trust_entity::{
    TrustEntity, TrustEntityRelations, TrustEntityRole, TrustEntityState, TrustEntityType,
};
use one_core::repository::trust_entity_repository::TrustEntityRepository;
use shared_types::TrustEntityId;
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
        name: &str,
        role: TrustEntityRole,
        state: TrustEntityState,
        trust_anchor: TrustAnchor,
        did: Did,
    ) -> TrustEntity {
        let trust_entity = TrustEntity {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deactivated_at: None,
            name: name.into(),
            logo: Some("Logo".to_owned()),
            website: Some("Website".to_owned()),
            terms_url: Some("TermsUrl".to_owned()),
            privacy_url: Some("PrivacyUrl".to_owned()),
            role,
            state,
            trust_anchor: Some(trust_anchor),
            entity_key: did.did.to_string(),
            r#type: TrustEntityType::Did,
            content: None,
            organisation: did.organisation,
        };

        self.repository.create(trust_entity.clone()).await.unwrap();

        trust_entity
    }

    pub async fn get(&self, id: TrustEntityId) -> Option<TrustEntity> {
        self.repository
            .get(
                id,
                &TrustEntityRelations {
                    trust_anchor: Some(TrustAnchorRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }
}
