use shared_types::TrustListSubscriptionId;

use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionListQuery,
    TrustListSubscriptionRelations,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListSubscriptionRepository: Send + Sync {
    async fn create(
        &self,
        entity: TrustListSubscription,
    ) -> Result<TrustListSubscriptionId, DataLayerError>;

    async fn get(
        &self,
        id: &TrustListSubscriptionId,
        relations: &TrustListSubscriptionRelations,
    ) -> Result<Option<TrustListSubscription>, DataLayerError>;

    async fn list(
        &self,
        query: TrustListSubscriptionListQuery,
    ) -> Result<GetTrustListSubscriptionList, DataLayerError>;

    async fn delete(&self, id: TrustListSubscriptionId) -> Result<(), DataLayerError>;
}
