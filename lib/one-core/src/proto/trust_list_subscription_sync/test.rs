use std::sync::Arc;

use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionState,
};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_list_subscription_sync::dto::{
    RemoteTrustCollection, RemoteTrustList, RemoteTrustListRole,
};
use crate::proto::trust_list_subscription_sync::{
    TrustListSubscriptionSync, TrustListSubscriptionSyncImpl,
};
use crate::provider::caching_loader::remote_trust_collection::MockRemoteTrustCollectionCache;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::test_utilities::{dummy_organisation, dummy_trust_collection};

const DUMMY_URL: &str = "https://example.com/trust-list";

#[tokio::test]
async fn test_sync_subscriptions_not_remote() {
    let trust_collection = test_collection(false);
    let proto = TrustListSubscriptionSyncImpl::new(
        Arc::new(MockRemoteTrustCollectionCache::new()),
        Arc::new(MockTrustListSubscriptionRepository::new()),
        Arc::new(NoTransactionManager),
    );
    let result = proto.sync_subscriptions(&trust_collection).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0401);
}

#[tokio::test]
async fn test_sync_subscriptions() {
    let remote_list = RemoteTrustCollection {
        name: "test collection".to_string(),
        trust_lists: vec![
            RemoteTrustList {
                name: "to be newly creted".to_string(),
                id: Uuid::new_v4().into(),
                role: RemoteTrustListRole::PidProvider,
                reference: "https://newly.created".to_string(),
                r#type: "test_provider".into(),
            },
            RemoteTrustList {
                name: "existing and remaining".to_string(),
                id: Uuid::new_v4().into(),
                role: RemoteTrustListRole::PidProvider,
                reference: "https://existing.com".to_string(),
                r#type: "test_provider".into(),
            },
        ],
    };

    let mut cache = MockRemoteTrustCollectionCache::new();
    cache
        .expect_get()
        .once()
        .returning(move |_| Ok(remote_list.clone()));
    let trust_collection = test_collection(true);
    let to_be_deleted = Uuid::new_v4().into();
    let local_collection_id = trust_collection.id;
    let mut repository = MockTrustListSubscriptionRepository::new();
    repository.expect_list().once().returning(move |_| {
        let now = crate::clock::now_utc();
        let trust_collection = TrustCollection {
            id: local_collection_id,
            ..dummy_trust_collection()
        };
        Ok(GetTrustListSubscriptionList {
            values: vec![
                TrustListSubscription {
                    id: Uuid::new_v4().into(),
                    name: "existing and remaining".to_string(),
                    created_date: now,
                    last_modified: now,
                    deactivated_at: None,
                    r#type: "test_provider".into(),
                    reference: "https://existing.com".to_string(),
                    role: Some(TrustListRoleEnum::PidProvider),
                    state: TrustListSubscriptionState::Active,
                    trust_collection: trust_collection.clone().into(),
                },
                TrustListSubscription {
                    id: to_be_deleted,
                    name: "existing and being deleted".to_string(),
                    created_date: now,
                    last_modified: now,
                    deactivated_at: None,
                    r#type: "test_provider".into(),
                    reference: "https://outdated.com".to_string(),
                    role: Some(TrustListRoleEnum::PidProvider),
                    state: TrustListSubscriptionState::Active,
                    trust_collection: trust_collection.into(),
                },
            ],
            total_pages: 1,
            total_items: 2,
        })
    });
    repository.expect_delete().once().returning(move |id| {
        assert_eq!(id, to_be_deleted);
        Ok(())
    });
    repository
        .expect_create()
        .once()
        .returning(|newly_created| {
            assert_eq!(newly_created.reference, "https://newly.created");
            Ok(Uuid::new_v4().into())
        });

    let proto = TrustListSubscriptionSyncImpl::new(
        Arc::new(cache),
        Arc::new(repository),
        Arc::new(NoTransactionManager),
    );
    proto.sync_subscriptions(&trust_collection).await.unwrap();
}

fn test_collection(is_remote: bool) -> TrustCollection {
    let now = crate::clock::now_utc();
    TrustCollection {
        ecosystem: "EUDI".into(),
        id: uuid::Uuid::new_v4().into(),
        name: "test".into(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: is_remote.then(|| Url::parse(DUMMY_URL).unwrap()),
        organisation: dummy_organisation(None).into(),
    }
}
