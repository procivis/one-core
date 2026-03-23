use std::sync::Arc;

use one_core::model::organisation::Organisation;
use one_core::model::trust_collection::{TrustCollection, TrustCollectionRelations};
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use shared_types::TrustCollectionId;
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub struct TrustCollectionDB {
    repository: Arc<dyn TrustCollectionRepository>,
}

#[derive(Default)]
pub struct TestTrustCollectionParams {
    pub id: Option<TrustCollectionId>,
    pub name: Option<String>,
    pub deactivated_at: Option<OffsetDateTime>,
    pub remote_trust_collection_url: Option<Url>,
}

impl TrustCollectionDB {
    pub fn new(repository: Arc<dyn TrustCollectionRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        params: TestTrustCollectionParams,
    ) -> TrustCollection {
        let trust_collection = TrustCollection {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: params.name.unwrap_or("collection".to_string()),
            deactivated_at: params.deactivated_at,
            remote_trust_collection_url: params.remote_trust_collection_url,
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
