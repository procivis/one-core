use std::collections::HashSet;
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
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::trust_list_subscription_sync::dto::{RemoteTrustCollection, RemoteTrustList};
use crate::provider::caching_loader::remote_trust_collection::RemoteTrustCollectionCache;
use crate::repository::error::DataLayerError;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

pub(crate) mod dto;
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
    cache: Arc<dyn RemoteTrustCollectionCache>,
    subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    transaction_manager: Arc<dyn TransactionManager>,
}

impl TrustListSubscriptionSyncImpl {
    pub fn new(
        cache: Arc<dyn RemoteTrustCollectionCache>,
        subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        transaction_manager: Arc<dyn TransactionManager>,
    ) -> Self {
        Self {
            cache,
            subscription_repository,
            transaction_manager,
        }
    }

    fn to_add(
        &self,
        remote_collection: &RemoteTrustCollection,
        existing_subscriptions: &GetTrustListSubscriptionList,
    ) -> Vec<RemoteTrustList> {
        let subscribed_references: HashSet<&str> = existing_subscriptions
            .values
            .iter()
            .map(|subscription| subscription.reference.as_str())
            .collect();

        remote_collection
            .trust_lists
            .iter()
            .filter(|list| !subscribed_references.contains(list.reference.as_str()))
            .cloned()
            .collect()
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

        let remote_collection = self
            .cache
            .get(url.as_str())
            .await
            .error_while("getting remote trust collection from cache")?;

        self.transaction_manager
            .tx(async {
                let existing_subscriptions: GetTrustListSubscriptionList = self
                    .subscription_repository
                    .list(TrustListSubscriptionListQuery {
                        include_count: false,
                        filtering: Some(
                            TrustListSubscriptionFilterValue::TrustCollectionId(vec![
                                trust_collection.id,
                            ])
                            .condition(),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("listing existing trust list subscriptions")?;

                // Subscriptions that are no longer advertised go first: uniqueness of both
                // the name and the reference is enforced per collection over the rows that
                // are not deactivated, so a list keeping its name while changing its
                // reference would collide with its own stale row if it were created before
                // that row is gone.
                let advertised_references: HashSet<&str> = remote_collection
                    .trust_lists
                    .iter()
                    .map(|list| list.reference.as_str())
                    .collect();
                let to_delete = existing_subscriptions
                    .values
                    .iter()
                    .filter(|s| !advertised_references.contains(s.reference.as_str()))
                    .map(|s| s.id);
                for id in to_delete {
                    self.subscription_repository
                        .delete(id)
                        .await
                        .error_while("deleting trust list subscription")?;
                }

                let to_add =
                    self.to_add(&remote_collection, &existing_subscriptions);
                for list in to_add {
                    let now = crate::clock::now_utc();
                    let (name, reference) = (list.name.clone(), list.reference.clone());
                    let result = self
                        .subscription_repository
                        .create(TrustListSubscription {
                            id: Uuid::new_v4().into(),
                            name: list.name,
                            created_date: now,
                            last_modified: now,
                            deactivated_at: None,
                            r#type: list.r#type,
                            reference: list.reference,
                            role: Some(list.role.into()),
                            state: TrustListSubscriptionState::Active,
                            trust_collection: trust_collection.clone().into(),
                        })
                        .await;
                    match result {
                        Ok(_) => {}
                        // The subscription may have been created by a concurrent sync, or a
                        // list that is still advertised - and hence not deleted above - may
                        // hold on to the name. Neither must abort the remaining lists.
                        Err(DataLayerError::AlreadyExists) => {
                            tracing::warn!(
                                "Skipping trust list `{name}` ({reference}) of trust collection {}: subscription already exists",
                                trust_collection.id,
                            );
                        }
                        Err(err) => {
                            return Err(err)
                                .error_while("creating trust list subscription")
                                .map_err(Into::into);
                        }
                    }
                }

                Ok::<_, TrustListSubscriptionSyncError>(())
            }
            .boxed())
            .await
            .error_while("syncing subscription")?
    }
}
