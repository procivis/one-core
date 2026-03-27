use std::sync::Arc;

use shared_types::{OrganisationId, TrustListSubscriptionId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionFilterValue,
    TrustListSubscriptionListQuery, TrustListSubscriptionRelations, TrustListSubscriptionState,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

pub struct TrustListSubscriptionHistoryDecorator {
    pub history_repository: Arc<dyn HistoryRepository>,
    pub inner: Arc<dyn TrustListSubscriptionRepository>,
    pub session_provider: Arc<dyn SessionProvider>,
}

#[async_trait::async_trait]
impl TrustListSubscriptionRepository for TrustListSubscriptionHistoryDecorator {
    async fn create(
        &self,
        trust_list_subscription: TrustListSubscription,
    ) -> Result<TrustListSubscriptionId, DataLayerError> {
        let trust_list_subscription_id = self.inner.create(trust_list_subscription.clone()).await?;

        self.write_history(
            trust_list_subscription_id,
            trust_list_subscription.name,
            HistoryAction::Created,
            trust_list_subscription
                .trust_collection
                .ok_or(DataLayerError::MappingError)?
                .organisation_id,
        )
        .await;

        Ok(trust_list_subscription_id)
    }

    async fn update_state(
        &self,
        id: TrustListSubscriptionId,
        state: TrustListSubscriptionState,
    ) -> Result<(), DataLayerError> {
        let existing_subscription = self.fetch_existing_trust_list_subscription(&id).await;

        self.inner.update_state(id, state).await?;

        let existing_subscription = existing_subscription?.ok_or(DataLayerError::MappingError)?;
        self.write_history(
            id,
            existing_subscription.name.to_owned(),
            HistoryAction::Updated,
            existing_subscription
                .trust_collection
                .ok_or(DataLayerError::MappingError)?
                .organisation_id,
        )
        .await;

        Ok(())
    }

    async fn get(
        &self,
        id: &TrustListSubscriptionId,
        relations: &TrustListSubscriptionRelations,
    ) -> Result<Option<TrustListSubscription>, DataLayerError> {
        self.inner.get(id, relations).await
    }

    async fn list(
        &self,
        query: TrustListSubscriptionListQuery,
    ) -> Result<GetTrustListSubscriptionList, DataLayerError> {
        self.inner.list(query).await
    }

    async fn delete(&self, id: TrustListSubscriptionId) -> Result<(), DataLayerError> {
        let existing_subscription = self.fetch_existing_trust_list_subscription(&id).await;
        self.inner.delete(id).await?;

        let existing_subscription = existing_subscription?.ok_or(DataLayerError::MappingError)?;
        self.write_history(
            id,
            existing_subscription.name,
            HistoryAction::Deleted,
            existing_subscription
                .trust_collection
                .ok_or(DataLayerError::MappingError)?
                .organisation_id,
        )
        .await;
        Ok(())
    }

    async fn delete_many(&self, ids: Vec<TrustListSubscriptionId>) -> Result<(), DataLayerError> {
        let Some(first_subscription_id) = ids.first() else {
            self.inner.delete_many(ids).await?;
            return Ok(());
        };
        let first_subscription = self
            .inner
            .get(
                first_subscription_id,
                &TrustListSubscriptionRelations {
                    // SAFETY: all trust list subscriptions should be in the same organisation
                    trust_collection: Some(Default::default()),
                },
            )
            .await;
        let existing_subscriptions = self
            .inner
            .list(TrustListSubscriptionListQuery {
                filtering: Some(TrustListSubscriptionFilterValue::Ids(ids.clone()).condition()),
                ..Default::default()
            })
            .await;

        self.inner.delete_many(ids).await?;

        let first_subscription = first_subscription?.ok_or(DataLayerError::MappingError)?;
        let existing_subscriptions = existing_subscriptions?.values;
        for existing_subscription in existing_subscriptions {
            self.write_history(
                existing_subscription.id,
                existing_subscription.name.to_owned(),
                HistoryAction::Deleted,
                first_subscription
                    .trust_collection
                    .as_ref()
                    .ok_or(DataLayerError::MappingError)?
                    .organisation_id,
            )
            .await;
        }
        Ok(())
    }
}

impl TrustListSubscriptionHistoryDecorator {
    async fn write_history(
        &self,
        id: TrustListSubscriptionId,
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
                source: HistorySource::Core,
                target: None,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::TrustListSubscription,
                metadata: None,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await;

        if let Err(err) = result {
            tracing::warn!("failed to insert trust list subscription history event: {err:?}");
        }
    }

    async fn fetch_existing_trust_list_subscription(
        &self,
        id: &TrustListSubscriptionId,
    ) -> Result<Option<TrustListSubscription>, DataLayerError> {
        self.get(
            id,
            &TrustListSubscriptionRelations {
                trust_collection: Some(Default::default()),
            },
        )
        .await
    }
}
