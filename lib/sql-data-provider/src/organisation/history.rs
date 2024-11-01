use std::sync::Arc;

use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use shared_types::OrganisationId;
use uuid::Uuid;

pub struct OrganisationHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn OrganisationRepository>,
}

#[async_trait::async_trait]
impl OrganisationRepository for OrganisationHistoryDecorator {
    async fn create_organisation(
        &self,
        request: Organisation,
    ) -> Result<OrganisationId, DataLayerError> {
        let organisation_id = self.inner.create_organisation(request.clone()).await?;

        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: request.created_date,
                action: HistoryAction::Created,
                entity_id: Some(organisation_id.into()),
                entity_type: HistoryEntityType::Organisation,
                metadata: None,
                organisation: Some(request),
            })
            .await;

        if let Err(err) = result {
            tracing::debug!("failed to insert organisation history event: {err:?}");
        }

        Ok(organisation_id)
    }

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        relations: &OrganisationRelations,
    ) -> Result<Option<Organisation>, DataLayerError> {
        self.inner.get_organisation(id, relations).await
    }

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError> {
        self.inner.get_organisation_list().await
    }
}
