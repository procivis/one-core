use std::sync::Arc;

use one_core::model::organisation::Organisation;
use one_core::model::trust_collection::{TrustCollection, TrustCollectionRelations};
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use shared_types::TrustCollectionId;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct TrustCollectionDB {
    repository: Arc<dyn TrustCollectionRepository>,
}

impl TrustCollectionDB {
    pub fn new(repository: Arc<dyn TrustCollectionRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: Organisation,
        id: Option<TrustCollectionId>,
    ) -> TrustCollection {
        let trust_collection = TrustCollection {
            id: id.unwrap_or(Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_string(),
            deactivated_at: None,
            remote_trust_collection_url: None,
            organisation_id: organisation.id,
            organisation: Some(organisation),
        };

        self.repository
            .create(trust_collection.clone())
            .await
            .unwrap();

        trust_collection
    }

    #[expect(unused)]
    pub async fn get(&self, id: TrustCollectionId) -> Option<TrustCollection> {
        self.repository
            .get(
                &id,
                &TrustCollectionRelations {
                    organisation: Some(Default::default()),
                },
            )
            .await
            .unwrap()
    }
}
