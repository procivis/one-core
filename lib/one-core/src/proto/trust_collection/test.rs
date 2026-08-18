use std::sync::Arc;

use mockall::predicate::eq;
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_collection::TrustCollectionManager;
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::proto::trust_collection::manager::TrustCollectionManagerImpl;
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::service::test_utilities::dummy_organisation;

const DUMMY_URL: &str = "https://example.com/trust-collection";
#[tokio::test]
async fn test_collection_sync() {
    let org_id = Uuid::new_v4().into();
    let mut repository = MockTrustCollectionRepository::new();

    let to_keep = test_collection("to_keep", org_id, true);
    let to_keep_clone = to_keep.clone();
    let to_delete = test_collection("to_delete", org_id, true);
    let to_delete_clone = to_delete.clone();
    let to_not_touch = test_collection("to_not_touch", org_id, false);
    let to_not_touch_clone = to_not_touch.clone();
    repository.expect_list().once().returning(move |_| {
        Ok(GetTrustCollectionList {
            values: vec![
                to_keep_clone.clone(),
                to_not_touch_clone.clone(),
                to_delete_clone.clone(),
            ],
            total_pages: 1,
            total_items: 3,
        })
    });
    repository
        .expect_delete()
        .once()
        .with(eq(to_delete.id))
        .returning(|_| Ok(()));
    repository
        .expect_create()
        .once()
        .withf(|c| c.name == "to_add" && c.remote_trust_collection_url.is_some())
        .returning(|c| Ok(c.id));

    let provider = TrustCollectionManagerImpl::new(
        Arc::new(repository),
        Arc::new(MockOrganisationRepository::default()),
        Arc::new(NoTransactionManager),
    );

    let to_add = remote_test_collection("to_add");
    let remote_collections = vec![
        remote_test_collection("to_keep"),
        to_add,
        // name interferes with a local collection it will simply be ignored
        remote_test_collection("to_not_touch"),
    ];
    let result = provider
        .sync_remote_trust_collections("https://provider.url", remote_collections, org_id)
        .await
        .unwrap();
    assert_eq!(result.len(), 2); // to_keep collection plus a new one create for "to_add"
    assert!(result.contains(&to_keep.id));
    assert!(!result.contains(&to_not_touch.id));
    assert!(!result.contains(&to_delete.id));
}

#[tokio::test]
async fn test_skip_already_existing() {
    let org_id = Uuid::new_v4().into();
    let mut repository = MockTrustCollectionRepository::new();
    repository
        .expect_create()
        .once()
        .withf(|c| c.name == "already_exists" && c.remote_trust_collection_url.is_some())
        .returning(|_| Err(DataLayerError::AlreadyExists));

    let provider = TrustCollectionManagerImpl::new(
        Arc::new(repository),
        Arc::new(MockOrganisationRepository::default()),
        Arc::new(NoTransactionManager),
    );

    let remote_collections = vec![remote_test_collection("already_exists")];
    let result = provider
        .create_empty_trust_collections("https://provider.url", remote_collections, org_id)
        .await
        .unwrap(); // does not fail
    assert!(result.is_empty()); // No new collections created
}

fn remote_test_collection(name: &str) -> RemoteTrustCollectionInfoDTO {
    RemoteTrustCollectionInfoDTO {
        id: Uuid::new_v4().into(),
        name: name.to_string(),
        ecosystem: "EUDI".into(),
    }
}

fn test_collection(
    name: &str,
    organisation_id: OrganisationId,
    is_remote: bool,
) -> TrustCollection {
    let now = crate::clock::now_utc();
    TrustCollection {
        ecosystem: "EUDI".into(),
        id: Uuid::new_v4().into(),
        name: name.to_owned(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: is_remote.then(|| Url::parse(DUMMY_URL).unwrap()),
        organisation: dummy_organisation(Some(organisation_id)).into(),
    }
}
