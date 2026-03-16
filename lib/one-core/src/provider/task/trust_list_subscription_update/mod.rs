mod dto;
mod model;

#[cfg(test)]
mod test;

use std::sync::Arc;

use serde_json::Value;
use shared_types::TrustListSubscriptionId;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, ErrorCodeMixin};
use crate::model::common::SortDirection;
use crate::model::history::{History, HistoryEntityType, HistorySource};
use crate::model::list_query::{ListPagination, ListSorting};
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, SortableTrustListSubscriptionColumn, TrustListSubscription,
    TrustListSubscriptionListQuery, TrustListSubscriptionRelations,
};
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::provider::task::Task;
use crate::provider::task::trust_list_subscription_update::NewState::Error;
use crate::provider::task::trust_list_subscription_update::dto::UpdateResultDTO;
use crate::provider::task::trust_list_subscription_update::model::{
    NewState, TrustListSubscriptionUpdateTaskError,
};
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::error::{MissingProviderError, ServiceError};

pub(crate) struct TrustListSubscriptionUpdateTask {
    subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl TrustListSubscriptionUpdateTask {
    pub fn new(
        subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
        subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            subscriber_provider,
            subscription_repository,
            history_repository,
            session_provider,
        }
    }

    async fn set_subscription_state(
        &self,
        subscription: &TrustListSubscription,
        state: NewState,
        updated_ids: &mut Vec<TrustListSubscriptionId>,
    ) -> Result<(), ServiceError> {
        if let Error(err) = &state {
            warn_log(subscription, err.as_ref());
        }
        let new_state = state.state();
        if subscription.state != new_state {
            self.subscription_repository
                .update_state(subscription.id, new_state)
                .await
                .error_while("updating subscription state")?;
            let org_id = subscription
                .trust_collection
                .as_ref()
                .ok_or_else(|| ServiceError::MappingError("trust collection missing".to_string()))?
                .organisation_id;

            updated_ids.push(subscription.id);
            let result = self
                .history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    action: state.action(),
                    name: subscription.name.clone(),
                    target: None,
                    source: HistorySource::Core,
                    entity_id: Some(subscription.id.into()),
                    entity_type: HistoryEntityType::TrustListSubscription,
                    metadata: state.metadata(),
                    organisation_id: Some(org_id),
                    user: self.session_provider.session().user(),
                })
                .await;
            if let Some(error) = result.err() {
                tracing::warn!("Failed to write trust list subscription history: {}", error);
            }
        }
        Ok(())
    }

    async fn load_subscription_batch(
        &self,
        page: u32,
    ) -> Result<GetTrustListSubscriptionList, ServiceError> {
        self.subscription_repository
            .list(TrustListSubscriptionListQuery {
                pagination: Some(ListPagination {
                    page,
                    page_size: 1000,
                }),
                sorting: Some(ListSorting {
                    column: SortableTrustListSubscriptionColumn::CreatedDate,
                    direction: Some(SortDirection::Ascending),
                }),
                filtering: None,
                include: None,
            })
            .await
            .error_while("getting trust list subscriptions")
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl Task for TrustListSubscriptionUpdateTask {
    async fn run(&self) -> Result<Value, ServiceError> {
        let mut page = 0;
        let mut result = UpdateResultDTO {
            updated_subscriptions: vec![],
            total_checks: 0,
        };

        loop {
            let subscription_list = self.load_subscription_batch(page).await?;

            for subscription in subscription_list.values {
                // reload with relation
                let subscription = self
                    .subscription_repository
                    .get(
                        &subscription.id,
                        &TrustListSubscriptionRelations {
                            trust_collection: Some(Default::default()),
                        },
                    )
                    .await
                    .error_while("getting trust list subscription")?
                    .ok_or_else(|| {
                        ServiceError::MappingError("trust list subscription missing".to_string())
                    })?;
                let Some(provider) = self.subscriber_provider.get(&subscription.r#type) else {
                    let err =
                        MissingProviderError::TrustListSubscriber(subscription.r#type.clone());
                    self.set_subscription_state(
                        &subscription,
                        err.into(),
                        &mut result.updated_subscriptions,
                    )
                    .await?;
                    continue;
                };
                let url = match Url::parse(&subscription.reference) {
                    Ok(url) => url,
                    Err(err) => {
                        let err = TrustListSubscriptionUpdateTaskError::from(err);
                        self.set_subscription_state(
                            &subscription,
                            err.into(),
                            &mut result.updated_subscriptions,
                        )
                        .await?;
                        continue;
                    }
                };
                let update_result = provider
                    .validate_subscription(&url, Some(subscription.role))
                    .await;
                match update_result {
                    Ok(_) => {
                        self.set_subscription_state(
                            &subscription,
                            NewState::Active,
                            &mut result.updated_subscriptions,
                        )
                        .await?
                    }
                    Err(err) => {
                        self.set_subscription_state(
                            &subscription,
                            err.into(),
                            &mut result.updated_subscriptions,
                        )
                        .await?
                    }
                }
                result.total_checks += 1;
            }
            page += 1;
            if (page as u64) >= subscription_list.total_pages {
                break;
            }
        }

        Ok(serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))?)
    }
}

fn warn_log(subscription: &TrustListSubscription, error: &dyn ErrorCodeMixin) {
    tracing::warn!(
        "Trust list subscription {} cannot be updated: {error}",
        subscription.id,
    );
}
