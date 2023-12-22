use std::sync::Arc;

use one_core::model::organisation::{Organisation, OrganisationId, OrganisationRelations};
use one_core::repository::organisation_repository::OrganisationRepository;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct OrganisationsDB {
    repository: Arc<dyn OrganisationRepository>,
}

impl OrganisationsDB {
    pub fn new(repository: Arc<dyn OrganisationRepository>) -> Self {
        Self { repository }
    }

    pub async fn get(&self, id: &OrganisationId) -> Organisation {
        self.repository
            .get_organisation(id, &OrganisationRelations {})
            .await
            .unwrap()
    }

    pub async fn create(&self) -> Organisation {
        let id = Uuid::new_v4();

        let organisation = Organisation {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };

        self.repository
            .create_organisation(organisation)
            .await
            .unwrap();

        self.get(&id).await
    }
}
