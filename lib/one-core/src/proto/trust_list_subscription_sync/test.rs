use std::sync::{Arc, Mutex};

use shared_types::{TrustCollectionId, TrustListSubscriptionId};
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
use crate::repository::error::DataLayerError;
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

#[tokio::test]
async fn test_sync_subscriptions_deletes_outdated_subscription_before_creating_replacement() {
    let trust_collection = test_collection(true);
    let collection_id = trust_collection.id;
    let outdated: TrustListSubscriptionId = Uuid::new_v4().into();

    // the advertised list kept its name and changed its reference
    let remote_collection = remote_collection(vec![remote_list("pid list", "https://new.list")]);
    let mut cache = MockRemoteTrustCollectionCache::new();
    cache
        .expect_get()
        .once()
        .returning(move |_| Ok(remote_collection.clone()));

    let calls = Arc::new(Mutex::new(vec![]));
    let mut repository = MockTrustListSubscriptionRepository::new();
    repository.expect_list().once().returning(move |_| {
        Ok(GetTrustListSubscriptionList {
            values: vec![existing_subscription(
                outdated,
                "pid list",
                "https://outdated.list",
                collection_id,
            )],
            total_pages: 1,
            total_items: 1,
        })
    });
    let delete_calls = calls.clone();
    repository.expect_delete().once().returning(move |id| {
        assert_eq!(id, outdated);
        delete_calls.lock().unwrap().push("delete");
        Ok(())
    });
    let create_calls = calls.clone();
    repository.expect_create().once().returning(move |created| {
        assert_eq!(created.name, "pid list");
        assert_eq!(created.reference, "https://new.list");
        create_calls.lock().unwrap().push("create");
        Ok(Uuid::new_v4().into())
    });

    let proto = TrustListSubscriptionSyncImpl::new(
        Arc::new(cache),
        Arc::new(repository),
        Arc::new(NoTransactionManager),
    );
    proto.sync_subscriptions(&trust_collection).await.unwrap();

    // the outdated subscription holds on to the name until it is deactivated
    assert_eq!(*calls.lock().unwrap(), vec!["delete", "create"]);
}

#[tokio::test]
async fn test_sync_subscriptions_continues_when_a_subscription_already_exists() {
    let trust_collection = test_collection(true);

    let remote_collection = remote_collection(vec![
        remote_list("first list", "https://first.list"),
        remote_list("second list", "https://second.list"),
    ]);
    let mut cache = MockRemoteTrustCollectionCache::new();
    cache
        .expect_get()
        .once()
        .returning(move |_| Ok(remote_collection.clone()));

    let created = Arc::new(Mutex::new(vec![]));
    let mut repository = MockTrustListSubscriptionRepository::new();
    repository
        .expect_list()
        .once()
        .returning(move |_| Ok(empty_subscription_list()));
    let create_calls = created.clone();
    repository
        .expect_create()
        .times(2)
        .returning(move |subscription| {
            create_calls
                .lock()
                .unwrap()
                .push(subscription.reference.clone());
            if subscription.reference == "https://first.list" {
                return Err(DataLayerError::AlreadyExists);
            }
            Ok(Uuid::new_v4().into())
        });

    let proto = TrustListSubscriptionSyncImpl::new(
        Arc::new(cache),
        Arc::new(repository),
        Arc::new(NoTransactionManager),
    );
    proto.sync_subscriptions(&trust_collection).await.unwrap();

    // the list that could not be created must not stop the ones behind it
    assert_eq!(
        *created.lock().unwrap(),
        vec!["https://first.list", "https://second.list"]
    );
}

fn remote_collection(trust_lists: Vec<RemoteTrustList>) -> RemoteTrustCollection {
    RemoteTrustCollection {
        name: "test collection".to_string(),
        trust_lists,
    }
}

fn remote_list(name: &str, reference: &str) -> RemoteTrustList {
    RemoteTrustList {
        name: name.to_string(),
        id: Uuid::new_v4().into(),
        role: RemoteTrustListRole::PidProvider,
        reference: reference.to_string(),
        r#type: "test_provider".into(),
    }
}

fn existing_subscription(
    id: TrustListSubscriptionId,
    name: &str,
    reference: &str,
    trust_collection_id: TrustCollectionId,
) -> TrustListSubscription {
    let now = crate::clock::now_utc();
    TrustListSubscription {
        id,
        name: name.to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: "test_provider".into(),
        reference: reference.to_string(),
        role: Some(TrustListRoleEnum::PidProvider),
        state: TrustListSubscriptionState::Active,
        trust_collection: TrustCollection {
            id: trust_collection_id,
            ..dummy_trust_collection()
        }
        .into(),
    }
}

fn empty_subscription_list() -> GetTrustListSubscriptionList {
    GetTrustListSubscriptionList {
        values: vec![],
        total_pages: 0,
        total_items: 0,
    }
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
