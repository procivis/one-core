use std::sync::Arc;

use one_core::model::organisation::{
    Organisation, OrganisationConfiguration, UpdateOrganisationRequest,
};
use one_core::model::relation::Related;
use one_core::repository::organisation_repository::OrganisationRepository;
use shared_types::OrganisationId;
use sql_data_provider::test_utilities::dummy_organisation;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct OrganisationsDB {
    repository: Arc<dyn OrganisationRepository>,
}

#[derive(Debug, Default)]
pub struct TestingOrganisationParams {
    pub id: Option<OrganisationId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub deactivated_at: Option<OffsetDateTime>,
    pub parent_organisation: Option<OrganisationId>,
    pub configuration: Option<OrganisationConfiguration>,
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

    pub async fn create_with(&self, params: TestingOrganisationParams) -> Organisation {
        let organisation = Organisation {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            parent_organisation: params
                .parent_organisation
                .map(|parent_id| Related::new(parent_id, self.repository.clone())),
            created_date: params.created_date.unwrap_or(one_core::clock::now_utc()),
            last_modified: params.last_modified.unwrap_or(one_core::clock::now_utc()),
            deactivated_at: params.deactivated_at,
            wallet_provider: None,
            wallet_provider_issuer: None,
            verifier_provider: None,
            verifier_provider_issuer: None,
            configuration: params.configuration.unwrap_or_default(),
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
