use std::sync::Arc;

use one_core::model::relation::Related;
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::{TrustListSubscription, TrustListSubscriptionState};
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use one_core::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use shared_types::{TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct TrustListSubscriptionDB {
    repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
}

impl TrustListSubscriptionDB {
    pub fn new(
        repository: Arc<dyn TrustListSubscriptionRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    ) -> Self {
        Self {
            repository,
            trust_collection_repository,
        }
    }

    pub async fn create(
        &self,
        name: &str,
        role: Option<TrustListRoleEnum>,
        r#type: impl Into<TrustListSubscriberId>,
        reference: &str,
        state: TrustListSubscriptionState,
        trust_collection_id: TrustCollectionId,
    ) -> TrustListSubscription {
        let trust_list_subscription = TrustListSubscription {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_string(),
            role,
            r#type: r#type.into(),
            deactivated_at: None,
            reference: reference.to_string(),
            state,
            trust_collection: Related::new(
                trust_collection_id,
                self.trust_collection_repository.clone(),
            ),
        };

        self.repository
            .create(trust_list_subscription.clone())
            .await
            .unwrap();

        trust_list_subscription
    }

    pub async fn get(&self, id: &TrustListSubscriptionId) -> TrustListSubscription {
        self.repository.get(id).await.unwrap()
    }
}
