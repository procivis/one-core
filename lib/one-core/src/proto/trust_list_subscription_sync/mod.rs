use std::sync::Arc;

use futures::FutureExt;
use shared_types::TrustCollectionId;
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionFilterValue,
    TrustListSubscriptionListQuery, TrustListSubscriptionState,
};
use crate::proto::http_client::HttpClient;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::trust_list_subscription_sync::dto::RemoteTrustCollection;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

mod dto;
#[cfg(test)]
mod test;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListSubscriptionSync: Send + Sync {
    async fn sync_subscriptions(
        &self,
        trust_collection: &TrustCollection,
    ) -> Result<(), TrustListSubscriptionSyncError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TrustListSubscriptionSyncError {
    #[error("Trust collection {0} is not a remote collection")]
    NotRemote(TrustCollectionId),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TrustListSubscriptionSyncError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotRemote(_) => ErrorCode::BR_0401,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

pub struct TrustListSubscriptionSyncImpl {
    client: Arc<dyn HttpClient>,
    subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    transaction_manager: Arc<dyn TransactionManager>,
}

impl TrustListSubscriptionSyncImpl {
    pub fn new(
        client: Arc<dyn HttpClient>,
        subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        transaction_manager: Arc<dyn TransactionManager>,
    ) -> Self {
        Self {
            client,
            subscription_repository,
            transaction_manager,
        }
    }
}

#[async_trait::async_trait]
impl TrustListSubscriptionSync for TrustListSubscriptionSyncImpl {
    async fn sync_subscriptions(
        &self,
        trust_collection: &TrustCollection,
    ) -> Result<(), TrustListSubscriptionSyncError> {
        let Some(url) = &trust_collection.remote_trust_collection_url else {
            return Err(TrustListSubscriptionSyncError::NotRemote(
                trust_collection.id,
            ));
        };

        let remote_collection: RemoteTrustCollection = async {
            self.client
                .get(url.as_str())
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("fetching remote trust collection")?
        .json()
        .error_while("parsing response")?;

        self.transaction_manager
            .tx(async {
                let existing_subscriptions: GetTrustListSubscriptionList = self
                    .subscription_repository
                    .list(TrustListSubscriptionListQuery {
                        filtering: Some(
                            TrustListSubscriptionFilterValue::TrustCollectionId(
                                trust_collection.id,
                            )
                            .condition(),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("listing existing trust list subscriptions")?;
                // remove the ones we already have
                let mut new_lists = remote_collection.trust_lists.clone();
                new_lists.retain(|list| {
                    existing_subscriptions
                        .values
                        .iter()
                        .any(|s| s.reference != list.reference)
                });

                let to_add = remote_collection
                    .trust_lists
                    .iter()
                    .filter(|s| {
                        !existing_subscriptions
                            .values
                            .iter()
                            .any(|list| list.reference == s.reference)
                    })
                    .cloned();

                for list in to_add {
                    let now = crate::clock::now_utc();
                    self.subscription_repository
                        .create(TrustListSubscription {
                            id: Uuid::new_v4().into(),
                            name: list.name,
                            created_date: now,
                            last_modified: now,
                            deactivated_at: None,
                            r#type: list.r#type,
                            reference: list.reference,
                            role: list.role.into(),
                            state: TrustListSubscriptionState::Active,
                            trust_collection_id: trust_collection.id,
                            trust_collection: Some(trust_collection.clone()),
                        })
                        .await
                        .error_while("creating trust list subscription")?;
                }

                let to_delete = existing_subscriptions
                    .values
                    .iter()
                    .filter(|s| {
                        !remote_collection
                            .trust_lists
                            .iter()
                            .any(|list| list.reference == s.reference)
                    })
                    .map(|s| s.id);
                for id in to_delete {
                    self.subscription_repository
                        .delete(id)
                        .await
                        .error_while("deleting trust list subscription")?;
                }
                Ok::<_, TrustListSubscriptionSyncError>(())
            }
            .boxed())
            .await
            .error_while("syncing subscription")?
    }
}
