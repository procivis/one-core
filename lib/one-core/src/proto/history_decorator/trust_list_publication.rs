use std::sync::Arc;

use anyhow::Context;
use shared_types::{OrganisationId, TrustListPublicationId};
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::organisation::OrganisationRelations;
use crate::model::trust_list_publication::{
    GetTrustListPublicationList, TrustListPublication, TrustListPublicationListQuery,
    TrustListPublicationRelations, UpdateTrustListPublicationRequest,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::trust_list_publication_repository::TrustListPublicationRepository;

pub struct TrustListPublicationHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn TrustListPublicationRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

#[async_trait::async_trait]
impl TrustListPublicationRepository for TrustListPublicationHistoryDecorator {
    async fn create(
        &self,
        entity: TrustListPublication,
    ) -> Result<TrustListPublicationId, DataLayerError> {
        let trust_list_publication_id = self.inner.create(entity.clone()).await?;

        self.write_history(
            trust_list_publication_id,
            entity.name,
            HistoryAction::Created,
            entity.organisation_id,
        )
        .await;

        Ok(trust_list_publication_id)
    }

    async fn update(
        &self,
        id: TrustListPublicationId,
        request: UpdateTrustListPublicationRequest,
    ) -> Result<(), DataLayerError> {
        let old_publication = self.get_trust_list_publication_by_id(id).await?;

        let updated = request.content.is_some() || request.sequence_number.is_some();

        self.inner.update(id, request).await?;

        // This is the first update, applied when the trust list publication is created
        // The CREATED history event is already written, we do not write an additional UPDATED event in this case
        if updated && old_publication.sequence_number != 0 {
            self.write_history(
                id,
                old_publication.name.to_owned(),
                HistoryAction::Updated,
                old_publication.organisation_id,
            )
            .await;
        }

        Ok(())
    }

    async fn list(
        &self,
        query: TrustListPublicationListQuery,
    ) -> Result<GetTrustListPublicationList, DataLayerError> {
        self.inner.list(query).await
    }

    async fn delete(&self, id: TrustListPublicationId) -> Result<(), DataLayerError> {
        let trust_list_publication = self.get_trust_list_publication_by_id(id).await?;
        self.inner.delete(id).await?;
        self.write_history(
            id,
            trust_list_publication.name,
            HistoryAction::Deleted,
            trust_list_publication.organisation_id,
        )
        .await;
        Ok(())
    }

    async fn get(
        &self,
        id: TrustListPublicationId,
        relations: &TrustListPublicationRelations,
    ) -> Result<Option<TrustListPublication>, DataLayerError> {
        self.inner.get(id, relations).await
    }
}

impl TrustListPublicationHistoryDecorator {
    async fn get_trust_list_publication_by_id(
        &self,
        id: TrustListPublicationId,
    ) -> Result<TrustListPublication, DataLayerError> {
        let trust_list_publication = self
            .inner
            .get(
                id,
                &TrustListPublicationRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .context("trust list publication is missing")?;

        Ok(trust_list_publication)
    }

    async fn write_history(
        &self,
        id: TrustListPublicationId,
        name: String,
        action: HistoryAction,
        organisation_id: OrganisationId,
    ) {
        let result = self
            .history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action,
                name,
                source: HistorySource::Core,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::TrustListPublication,
                metadata: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert trust list publication history event: {err:?}");
        }
    }
}
