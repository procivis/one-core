use std::sync::Arc;

use one_core::model::organisation::OrganisationRelations;
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRelations};
use one_core::model::trust_entity::{TrustEntity, TrustEntityRelations, TrustEntityRole};
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
        entity_id: &str,
        name: &str,
        role: TrustEntityRole,
        trust_anchor: TrustAnchor,
    ) -> TrustEntity {
        let trust_entity = TrustEntity {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            entity_id: entity_id.into(),
            name: name.into(),
            logo: Some("Logo".to_owned()),
            website: Some("Website".to_owned()),
            terms_url: Some("TermsUrl".to_owned()),
            privacy_url: Some("PrivacyUrl".to_owned()),
            role,
            trust_anchor: Some(trust_anchor),
        };

        self.repository.create(trust_entity.clone()).await.unwrap();

        trust_entity
    }

    pub async fn get(&self, id: TrustEntityId) -> Option<TrustEntity> {
        self.repository
            .get(
                id,
                &TrustEntityRelations {
                    trust_anchor: Some(TrustAnchorRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                },
            )
            .await
            .unwrap()
    }
}
