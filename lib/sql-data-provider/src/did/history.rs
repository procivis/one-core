use std::sync::Arc;

use anyhow::Context;
use one_core::model::did::{Did, DidListQuery, DidRelations, GetDidList, UpdateDidRequest};
use one_core::model::history::{History, HistoryAction, HistoryEntityType};
use one_core::repository::did_repository::DidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::HistoryRepository;
use shared_types::{DidId, DidValue, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct DidHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn DidRepository>,
}

impl DidHistoryDecorator {
    async fn create_history(
        &self,
        id: DidId,
        name: String,
        action: HistoryAction,
        organisation_id: OrganisationId,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                action,
                name,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Did,
                metadata: None,
                organisation_id,
            })
            .await;

        if let Err(error) = result {
            tracing::warn!(%error, "failed to insert did history event");
        }
    }
}

#[async_trait::async_trait]
impl DidRepository for DidHistoryDecorator {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        let id = request.id;
        let name = request.name.clone();
        let organisation_id = request.organisation.as_ref().map(|o| o.id);
        let did_id = self.inner.create_did(request).await?;

        if let Some(organisation_id) = organisation_id {
            self.create_history(id, name, HistoryAction::Created, organisation_id)
                .await;
        } else {
            tracing::warn!("did (id: {did_id}) missing organisation");
        }

        Ok(did_id)
    }

    async fn get_did(
        &self,
        id: &DidId,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError> {
        self.inner.get_did(id, relations).await
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        organisation: Option<Option<OrganisationId>>,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError> {
        self.inner
            .get_did_by_value(value, organisation, relations)
            .await
    }

    async fn get_did_list(&self, query: DidListQuery) -> Result<GetDidList, DataLayerError> {
        self.inner.get_did_list(query).await
    }

    async fn update_did(&self, request: UpdateDidRequest) -> Result<(), DataLayerError> {
        self.inner.update_did(request.clone()).await?;

        if request.deactivated.is_none() {
            return Ok(());
        };

        let did = self
            .inner
            .get_did(
                &request.id,
                &DidRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("did is missing")?;

        if let Some(organisation) = did.organisation {
            self.create_history(
                did.id,
                did.name,
                HistoryAction::Deactivated,
                organisation.id,
            )
            .await;
        } else {
            tracing::warn!("did (id: {}) missing organisation", request.id);
        }

        Ok(())
    }
}
