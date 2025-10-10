use std::sync::Arc;

use anyhow::Context;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::{Organisation, OrganisationRelations, UpdateOrganisationRequest};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::organisation_repository::OrganisationRepository;

pub struct OrganisationHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn OrganisationRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

impl OrganisationHistoryDecorator {
    async fn write_history(
        &self,
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
                entity_id: Some(organisation_id.into()),
                entity_type: HistoryEntityType::Organisation,
                metadata: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert organisation history event: {err:?}");
        }
    }
}

#[async_trait::async_trait]
impl OrganisationRepository for OrganisationHistoryDecorator {
    async fn create_organisation(
        &self,
        request: Organisation,
    ) -> Result<OrganisationId, DataLayerError> {
        let organisation_id = self.inner.create_organisation(request.clone()).await?;

        self.write_history(request.name, HistoryAction::Created, organisation_id)
            .await;

        Ok(organisation_id)
    }

    async fn update_organisation(
        &self,
        request: UpdateOrganisationRequest,
    ) -> Result<(), DataLayerError> {
        self.inner.update_organisation(request.clone()).await?;

        let updated_entry = self
            .inner
            .get_organisation(&request.id, &OrganisationRelations::default())
            .await?
            .context("organisation missing")?;

        if request.name.is_some()
            || request.wallet_provider_issuer.is_some()
            || request.wallet_provider.is_some()
        {
            self.write_history(
                updated_entry.name.to_owned(),
                HistoryAction::Updated,
                updated_entry.id,
            )
            .await;
        }

        if let Some(deactivate) = request.deactivate {
            self.write_history(
                updated_entry.name,
                if deactivate {
                    HistoryAction::Deactivated
                } else {
                    HistoryAction::Reactivated
                },
                updated_entry.id,
            )
            .await;
        }

        Ok(())
    }

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        relations: &OrganisationRelations,
    ) -> Result<Option<Organisation>, DataLayerError> {
        self.inner.get_organisation(id, relations).await
    }

    async fn get_organisation_for_wallet_provider(
        &self,
        wallet_provider: &str,
    ) -> Result<Option<Organisation>, DataLayerError> {
        self.inner
            .get_organisation_for_wallet_provider(wallet_provider)
            .await
    }

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError> {
        self.inner.get_organisation_list().await
    }
}
