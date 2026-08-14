use std::sync::Arc;

use one_core::model::organisation::{Organisation, UpdateOrganisationRequest};
use one_core::model::relation::Related;
use one_core::repository::organisation_repository::OrganisationRepository;
use shared_types::OrganisationId;
use sql_data_provider::test_utilities::dummy_organisation;

pub struct OrganisationsDB {
    repository: Arc<dyn OrganisationRepository>,
}

impl OrganisationsDB {
    pub fn new(repository: Arc<dyn OrganisationRepository>) -> Self {
        Self { repository }
    }

    pub async fn get(&self, id: &OrganisationId) -> Organisation {
        self.repository.get_organisation(id).await.unwrap()
    }

    pub async fn create(&self) -> Organisation {
        let organisation = dummy_organisation(None);

        self.repository
            .create_organisation(organisation.clone())
            .await
            .unwrap();

        self.get(&organisation.id).await
    }

    pub async fn create_with_parent(&self, parent_id: OrganisationId) -> Organisation {
        let organisation = Organisation {
            parent_organisation: Some(Related::new(parent_id, self.repository.clone())),
            ..dummy_organisation(None)
        };

        self.repository
            .create_organisation(organisation.clone())
            .await
            .unwrap();

        self.get(&organisation.id).await
    }

    pub async fn deactivate(&self, id: &OrganisationId) {
        self.repository
            .update_organisation(
                id,
                UpdateOrganisationRequest {
                    deactivate: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    pub async fn update(&self, id: &OrganisationId, request: UpdateOrganisationRequest) {
        self.repository
            .update_organisation(id, request)
            .await
            .unwrap();
    }
}
