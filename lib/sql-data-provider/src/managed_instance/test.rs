use one_core::model::instance::{InstanceRole, InstanceStatus};
use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::managed_instance::{
    ManagedInstance, ManagedInstanceFilterValue, ManagedInstanceListQuery, ManagedInstanceOs,
    SortableManagedInstanceColumn, UpdateManagedInstanceRequest,
};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use one_core::repository::managed_instance_repository::ManagedInstanceRepository;
use one_core::service::test_utilities::dummy_organisation;
use shared_types::{ManagedInstanceId, OrganisationId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ManagedInstanceProvider;
use crate::test_utilities::{
    get_dummy_date, insert_organisation_to_database, insert_wallet_instance_to_database,
    random_jwk, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: ManagedInstanceProvider,
    pub wallet_unit_ids: Vec<ManagedInstanceId>,
    pub organisation_id: OrganisationId,
}

async fn setup(n: usize) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let mut wallet_unit_ids = vec![];
    for i in 0..n {
        let wallet_unit_id =
            insert_wallet_instance_to_database(&db, organisation_id, format!("wallet{i}")).await;
        wallet_unit_ids.push(wallet_unit_id);
    }

    TestSetup {
        provider: ManagedInstanceProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository: data_layer.organisation_repository,
            managed_instance_attestation_repository: data_layer
                .managed_instance_attestation_repository,
        },
        organisation_id,
        wallet_unit_ids,
    }
}

fn dummy_managed_instance(id: ManagedInstanceId, org: OrganisationId) -> ManagedInstance {
    let now = get_dummy_date();
    ManagedInstance {
        id,
        created_date: now,
        last_modified: now,
        last_issuance: Some(now),
        name: "test_wallet".to_string(),
        os: ManagedInstanceOs::Android,
        role: InstanceRole::Wallet,
        status: InstanceStatus::Active,
        provider: "Test Provider Name".to_string(),
        authentication_key_jwk: Some(random_jwk()),
        nonce: None,
        user_nonce: None,
        user_sub: None,
        verifier_csr: None,
        verifier_signature_ids: None,
        organisation: Organisation {
            created_date: now,
            last_modified: now,
            ..dummy_organisation(Some(org))
        }
        .into(),
        attestations: Default::default(),
        version: None,
    }
}

#[tokio::test]
async fn test_create_wallet_instance_success() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);

    let result = provider.create(wallet_unit.clone()).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), wallet_unit_id);

    // Verify the wallet unit was actually created in the database
    let stored_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();
    assert_eq!(stored_wallet_instance.id, wallet_unit.id);
    assert_eq!(stored_wallet_instance.name, wallet_unit.name);
    assert_eq!(stored_wallet_instance.os, wallet_unit.os);
    assert_eq!(stored_wallet_instance.status, wallet_unit.status);
    assert_eq!(stored_wallet_instance.provider, wallet_unit.provider);
    assert_eq!(stored_wallet_instance.provider, wallet_unit.provider);
    assert_eq!(
        stored_wallet_instance.authentication_key_jwk,
        wallet_unit.authentication_key_jwk
    );
}

#[tokio::test]
async fn test_create_wallet_instance_duplicate_id() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let wallet_unit1 = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);

    // Create first wallet unit
    let result1 = provider.create(wallet_unit1).await;
    assert!(result1.is_ok());

    // Try to create second wallet unit with same ID - should fail
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id, Uuid::new_v4().into());
    wallet_unit2.authentication_key_jwk = Some(random_jwk());

    let result2 = provider.create(wallet_unit2).await;
    assert!(result2.is_err());
}

#[tokio::test]
async fn test_create_wallet_instance_duplicate_public_key() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();

    let wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);

    // Create first wallet unit
    let result1 = provider.create(wallet_unit1.clone()).await;
    assert!(result1.is_ok());

    // Try to create second wallet unit with same public key - should fail
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.authentication_key_jwk = wallet_unit1.authentication_key_jwk; // Same public key

    let result2 = provider.create(wallet_unit2).await;
    assert!(result2.is_err());
}

#[tokio::test]
async fn test_create_wallet_instance_different_statuses() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Test creating with ACTIVE status
    let active_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut active_wallet_instance = dummy_managed_instance(active_id, test_setup.organisation_id);
    active_wallet_instance.status = InstanceStatus::Active;

    let result_active = provider.create(active_wallet_instance).await;
    assert!(result_active.is_ok());

    // Test creating with REVOKED status
    let revoked_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut revoked_wallet_instance =
        dummy_managed_instance(revoked_id, test_setup.organisation_id);
    revoked_wallet_instance.status = InstanceStatus::Revoked;

    let result_revoked = provider.create(revoked_wallet_instance).await;
    assert!(result_revoked.is_ok());

    // Verify both were created with correct statuses
    let active_stored = provider.get(&active_id).await.unwrap();
    assert_eq!(active_stored.status, InstanceStatus::Active);

    let revoked_stored = provider.get(&revoked_id).await.unwrap();
    assert_eq!(revoked_stored.status, InstanceStatus::Revoked);
}

#[tokio::test]
async fn test_create_wallet_instance_different_os_types() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Test creating with ANDROID OS
    let android_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut android_wallet_instance =
        dummy_managed_instance(android_id, test_setup.organisation_id);
    android_wallet_instance.os = ManagedInstanceOs::Android;

    let result_android = provider.create(android_wallet_instance).await;
    assert!(result_android.is_ok());

    // Test creating with iOS OS
    let ios_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut ios_wallet_instance = dummy_managed_instance(ios_id, test_setup.organisation_id);
    ios_wallet_instance.os = ManagedInstanceOs::Ios;

    let result_ios = provider.create(ios_wallet_instance).await;
    assert!(result_ios.is_ok());

    // Verify both were created with correct OS types
    let android_stored = provider.get(&android_id).await.unwrap();
    assert_eq!(android_stored.os, ManagedInstanceOs::Android);

    let ios_stored = provider.get(&ios_id).await.unwrap();
    assert_eq!(ios_stored.os, ManagedInstanceOs::Ios);
}

#[tokio::test]
async fn test_create_and_list_wallet_instances() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create multiple wallet units
    let mut created_ids = Vec::new();

    for i in 0..3 {
        let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = format!("wallet_{i}");

        let result = provider.create(wallet_unit).await;
        assert!(result.is_ok());
        created_ids.push(wallet_unit_id);
    }

    // List all wallet units
    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_items.unwrap(), 3);
    assert_eq!(data.values.len(), 3);

    // Verify all created wallet units are in the list
    for created_id in created_ids {
        assert!(data.values.iter().any(|wu| wu.id == created_id));
    }
}

#[tokio::test]
async fn test_get_wallet_instance_success() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        ..
    } = setup(1).await;

    let result = provider.get(&wallet_unit_ids[0]).await;

    assert!(result.is_ok());
    let wallet_unit = result.unwrap();
    assert_eq!(wallet_unit.id, wallet_unit_ids[0]);
    assert_eq!(wallet_unit.name, "wallet0");
    assert_eq!(wallet_unit.os, ManagedInstanceOs::Android);
    assert_eq!(wallet_unit.status, InstanceStatus::Active);
    assert_eq!(wallet_unit.provider, "Test Provider Name");
    assert!(wallet_unit.authentication_key_jwk.is_some());
}

#[tokio::test]
async fn test_get_wallet_instance_missing() {
    let TestSetup { provider, .. } = setup(0).await;

    let result = provider.get(&Uuid::new_v4().into()).await;

    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
}

#[tokio::test]
async fn test_get_wallet_instance_list_no_filters() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        ..
    } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 1);
    assert_eq!(data.total_items.unwrap(), 3);
    assert_eq!(data.values.len(), 3);

    assert!(
        data.values
            .iter()
            .all(|wu| wallet_unit_ids.contains(&wu.id))
    );
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_pagination() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 2,
        }),
        sorting: None,
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 2);
    assert_eq!(data.total_items.unwrap(), 3);
    assert_eq!(data.values.len(), 2);
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_name_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::Name(one_core::model::list_filter::StringMatch::equals(
                "wallet1",
            ))
            .condition(),
        ),
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 1);
    assert_eq!(data.total_items.unwrap(), 1);
    assert_eq!(data.values.len(), 1);
    assert_eq!(data.values[0].name, "wallet1");
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_status_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::Status(vec![InstanceStatus::Active]).condition(),
        ),
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 1);
    assert_eq!(data.total_items.unwrap(), 3);
    assert_eq!(data.values.len(), 3);
    assert!(
        data.values
            .iter()
            .all(|wu| wu.status == InstanceStatus::Active)
    );
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_sorting() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 1);
    assert_eq!(data.total_items.unwrap(), 3);
    assert_eq!(data.values.len(), 3);

    // Check that names are sorted in ascending order
    let names: Vec<&String> = data.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(names, vec!["wallet0", "wallet1", "wallet2"]);
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_ids_filter() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        ..
    } = setup(3).await;

    let target_ids = vec![wallet_unit_ids[0], wallet_unit_ids[2]];

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(ManagedInstanceFilterValue::Ids(target_ids.clone()).condition()),
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 1);
    assert_eq!(data.total_items.unwrap(), 2);
    assert_eq!(data.values.len(), 2);

    let returned_ids: Vec<ManagedInstanceId> = data.values.iter().map(|wu| wu.id).collect();
    assert!(target_ids.iter().all(|id| returned_ids.contains(id)));
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_wallet_provider_name_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::ProviderName(vec!["Test Provider Name".to_string()])
                .condition(),
        ),
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 1);
    assert_eq!(data.total_items.unwrap(), 3);
    assert_eq!(data.values.len(), 3);
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_os_filter() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::Os(vec![ManagedInstanceOs::Android]).condition(),
        ),
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 1);
    assert_eq!(data.total_items.unwrap(), 3);
    assert_eq!(data.values.len(), 3);
    assert!(
        data.values
            .iter()
            .all(|wu| wu.os == ManagedInstanceOs::Android)
    );
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_user_sub_filter() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        organisation_id,
    } = setup(3).await;

    // Set user_sub only on the first wallet instance
    provider
        .update(
            &wallet_unit_ids[0],
            UpdateManagedInstanceRequest {
                user_sub: Some("sub-alice".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::OrganisationId(organisation_id).condition()
                & ManagedInstanceFilterValue::UserSub(
                    one_core::model::list_filter::StringMatch::equals("sub-alice".to_string()),
                ),
        ),
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();
    assert_eq!(result.total_items.unwrap(), 1);
    assert_eq!(result.values[0].id, wallet_unit_ids[0]);
    assert_eq!(result.values[0].user_sub.as_deref(), Some("sub-alice"));
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_user_sub_prefix_filter() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        organisation_id,
    } = setup(3).await;

    provider
        .update(
            &wallet_unit_ids[0],
            UpdateManagedInstanceRequest {
                user_sub: Some("user|alice".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    provider
        .update(
            &wallet_unit_ids[1],
            UpdateManagedInstanceRequest {
                user_sub: Some("user|bob".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::OrganisationId(organisation_id).condition()
                & ManagedInstanceFilterValue::UserSub(
                    one_core::model::list_filter::StringMatch::starts_with("user|".to_string()),
                ),
        ),
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();
    assert_eq!(result.total_items.unwrap(), 2);
}

#[tokio::test]
async fn test_get_wallet_instance_list_with_user_sub_sorting() {
    let TestSetup {
        provider,
        wallet_unit_ids,
        ..
    } = setup(3).await;

    for (id, sub) in wallet_unit_ids.iter().zip(["charlie", "alice", "bob"]) {
        provider
            .update(
                id,
                UpdateManagedInstanceRequest {
                    user_sub: Some(sub.to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::UserSub,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();
    assert_eq!(result.total_items.unwrap(), 3);
    let subs: Vec<Option<&str>> = result
        .values
        .iter()
        .map(|wu| wu.user_sub.as_deref())
        .collect();
    assert_eq!(subs, vec![Some("alice"), Some("bob"), Some("charlie")]);
}

#[tokio::test]
async fn test_get_wallet_instance_list_empty_result() {
    let TestSetup { provider, .. } = setup(3).await;

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::Status(vec![InstanceStatus::Revoked]).condition(),
        ),
        include: None,
    };

    let result = provider.get_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages.unwrap(), 0);
    assert_eq!(data.total_items.unwrap(), 0);
    assert_eq!(data.values.len(), 0);
}

// UPDATE TESTS - Status-only updates

#[tokio::test]
async fn test_update_wallet_instance_status_success() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create a wallet unit first with ACTIVE status
    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
    wallet_unit.status = InstanceStatus::Active;
    let original_name = wallet_unit.name.clone();
    let original_os = wallet_unit.os;
    let original_provider_name = wallet_unit.provider.clone();
    let original_public_key = wallet_unit.authentication_key_jwk.clone();

    provider.create(wallet_unit).await.unwrap();

    // Update only the status to REVOKED
    let update_request = UpdateManagedInstanceRequest {
        status: Some(InstanceStatus::Revoked),
        ..Default::default()
    };

    let result = provider.update(&wallet_unit_id, update_request).await;
    assert!(result.is_ok());

    // Verify only the status and last_modified were updated
    let updated_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();

    // Status should be updated
    assert_eq!(updated_wallet_instance.status, InstanceStatus::Revoked);

    // All other fields should remain unchanged
    assert_eq!(updated_wallet_instance.name, original_name);
    assert_eq!(updated_wallet_instance.os, original_os);
    assert_eq!(updated_wallet_instance.provider, original_provider_name);
    assert_eq!(
        updated_wallet_instance.authentication_key_jwk,
        original_public_key
    );

    // Verify last_modified was updated (should be different from created_date)
    assert!(updated_wallet_instance.last_modified > updated_wallet_instance.created_date);
}

#[tokio::test]
async fn test_update_wallet_instance_nonexistent() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let nonexistent_id: ManagedInstanceId = Uuid::new_v4().into();
    let update_request = UpdateManagedInstanceRequest {
        status: Some(InstanceStatus::Revoked),
        ..Default::default()
    };

    let result = provider.update(&nonexistent_id, update_request).await;

    // Should fail because the wallet unit doesn't exist
    assert!(result.is_err());
}

#[tokio::test]
async fn test_update_wallet_instance_empty_request() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create a wallet unit first
    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
    let original_status = wallet_unit.status;
    provider.create(wallet_unit).await.unwrap();

    // Get original last_modified
    let original_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();

    // Update with empty request (no fields specified)
    let update_request = UpdateManagedInstanceRequest::default();

    let result = provider.update(&wallet_unit_id, update_request).await;
    assert!(result.is_ok());

    // Verify no fields were changed except last_modified
    let updated_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();

    assert_eq!(updated_wallet_instance.status, original_status);
    // But last_modified should be updated
    assert!(updated_wallet_instance.last_modified > original_wallet_instance.last_modified);
}

#[tokio::test]
async fn test_update_wallet_instance_status_changes() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet unit with ACTIVE status
    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
    wallet_unit.status = InstanceStatus::Active;
    provider.create(wallet_unit).await.unwrap();

    // Update to REVOKED
    let update_request = UpdateManagedInstanceRequest {
        status: Some(InstanceStatus::Revoked),
        ..Default::default()
    };

    let result = provider.update(&wallet_unit_id, update_request).await;
    assert!(result.is_ok());

    // Verify status was updated
    let updated_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();
    assert_eq!(updated_wallet_instance.status, InstanceStatus::Revoked);

    // Update back to ACTIVE
    let update_request = UpdateManagedInstanceRequest {
        status: Some(InstanceStatus::Active),
        ..Default::default()
    };

    let result = provider.update(&wallet_unit_id, update_request).await;
    assert!(result.is_ok());

    // Verify status was updated back
    let updated_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();
    assert_eq!(updated_wallet_instance.status, InstanceStatus::Active);
}

#[tokio::test]
async fn test_update_wallet_instance_public_key_changes() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
    wallet_unit.authentication_key_jwk = None;
    provider.create(wallet_unit).await.unwrap();
    let created_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();
    assert_eq!(created_wallet_instance.authentication_key_jwk, None);

    let new_jwk = random_jwk();
    let update_request = UpdateManagedInstanceRequest {
        authentication_key_jwk: Some(new_jwk.clone()),
        ..Default::default()
    };

    let result = provider.update(&wallet_unit_id, update_request).await;
    assert!(result.is_ok());

    // Verify public key was updated
    let updated_wallet_instance = provider.get(&wallet_unit_id).await.unwrap();
    assert_eq!(
        updated_wallet_instance.authentication_key_jwk,
        Some(new_jwk)
    );
}

#[tokio::test]
async fn test_update_and_list_wallet_instances() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create multiple wallet units
    let mut wallet_unit_ids = Vec::new();
    for i in 0..3 {
        let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = format!("wallet_{i}");
        wallet_unit.status = InstanceStatus::Active;

        provider.create(wallet_unit).await.unwrap();
        wallet_unit_ids.push(wallet_unit_id);
    }

    // Update one wallet unit to REVOKED status
    let update_request = UpdateManagedInstanceRequest {
        status: Some(InstanceStatus::Revoked),
        ..Default::default()
    };

    provider
        .update(&wallet_unit_ids[1], update_request)
        .await
        .unwrap();

    // List only ACTIVE wallet units
    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            ManagedInstanceFilterValue::Status(vec![InstanceStatus::Active]).condition(),
        ),
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    // Should only return 2 ACTIVE wallet units
    assert_eq!(result.total_items.unwrap(), 2);
    assert_eq!(result.values.len(), 2);
    assert!(
        result
            .values
            .iter()
            .all(|wu| wu.status == InstanceStatus::Active)
    );

    // Verify the revoked one is not in the list
    assert!(!result.values.iter().any(|wu| wu.id == wallet_unit_ids[1]));
}

// SORTING TESTS

#[tokio::test]
async fn test_sort_by_name_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different names
    let names = vec!["zebra_wallet", "alpha_wallet", "beta_wallet"];
    for name in &names {
        let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = name.to_string();
        provider.create(wallet_unit).await.unwrap();
    }

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 3);
    let returned_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(
        returned_names,
        vec!["alpha_wallet", "beta_wallet", "zebra_wallet"]
    );
}

#[tokio::test]
async fn test_sort_by_name_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different names
    let names = vec!["zebra_wallet", "alpha_wallet", "beta_wallet"];
    for name in &names {
        let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = name.to_string();
        provider.create(wallet_unit).await.unwrap();
    }

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 3);
    let returned_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(
        returned_names,
        vec!["zebra_wallet", "beta_wallet", "alpha_wallet"]
    );
}

#[tokio::test]
async fn test_sort_by_status_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different statuses
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "revoked_wallet".to_string();
    wallet_unit1.status = InstanceStatus::Revoked;
    provider.create(wallet_unit1).await.unwrap();

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "active_wallet".to_string();
    wallet_unit2.status = InstanceStatus::Active;
    provider.create(wallet_unit2).await.unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Status,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);
    // ACTIVE should come before REVOKED alphabetically
    assert_eq!(result.values[0].status, InstanceStatus::Active);
    assert_eq!(result.values[1].status, InstanceStatus::Revoked);
}

#[tokio::test]
async fn test_sort_by_status_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different statuses
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "revoked_wallet".to_string();
    wallet_unit1.status = InstanceStatus::Revoked;
    provider.create(wallet_unit1).await.unwrap();

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "active_wallet".to_string();
    wallet_unit2.status = InstanceStatus::Active;
    provider.create(wallet_unit2).await.unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Status,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);
    // REVOKED should come before ACTIVE in descending order
    assert_eq!(result.values[0].status, InstanceStatus::Revoked);
    assert_eq!(result.values[1].status, InstanceStatus::Active);
}

#[tokio::test]
async fn test_sort_by_os_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different OS values
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "ios_wallet".to_string();
    wallet_unit1.os = ManagedInstanceOs::Ios;
    provider.create(wallet_unit1).await.unwrap();

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "android_wallet".to_string();
    wallet_unit2.os = ManagedInstanceOs::Android;
    provider.create(wallet_unit2).await.unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Os,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);
    // ANDROID should come before IOS alphabetically
    assert_eq!(result.values[0].os, ManagedInstanceOs::Android);
    assert_eq!(result.values[1].os, ManagedInstanceOs::Ios);
}

#[tokio::test]
async fn test_sort_by_os_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different OS values
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "ios_wallet".to_string();
    wallet_unit1.os = ManagedInstanceOs::Ios;
    provider.create(wallet_unit1).await.unwrap();

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "android_wallet".to_string();
    wallet_unit2.os = ManagedInstanceOs::Android;
    provider.create(wallet_unit2).await.unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Os,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);
    // IOS should come before ANDROID in descending order
    assert_eq!(result.values[0].os, ManagedInstanceOs::Ios);
    assert_eq!(result.values[1].os, ManagedInstanceOs::Android);
}

#[tokio::test]
async fn test_sort_by_created_date_ascending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with sufficient delay to ensure different timestamps
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "first_wallet".to_string();
    provider.create(wallet_unit1).await.unwrap();

    // Larger delay to ensure different created_date
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "second_wallet".to_string();
    provider.create(wallet_unit2).await.unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::CreatedDate,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);

    // Verify timestamps are properly ordered
    assert!(result.values[0].created_date <= result.values[1].created_date);

    // If timestamps are identical, just verify both are present
    if result.values[0].created_date == result.values[1].created_date {
        let names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
        assert!(names.contains(&&"first_wallet".to_string()));
        assert!(names.contains(&&"second_wallet".to_string()));
    } else {
        // First created should come first in ascending order
        assert_eq!(result.values[0].name, "first_wallet");
        assert_eq!(result.values[1].name, "second_wallet");
    }
}

#[tokio::test]
async fn test_sort_by_created_date_descending() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with sufficient delay to ensure different timestamps
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "first_wallet".to_string();
    provider.create(wallet_unit1).await.unwrap();

    // Larger delay to ensure different created_date
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "second_wallet".to_string();
    provider.create(wallet_unit2).await.unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::CreatedDate,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);

    // Verify timestamps are actually different
    assert!(result.values[0].created_date >= result.values[1].created_date);

    // If timestamps are identical, we can't rely on order, so just verify we have both
    if result.values[0].created_date == result.values[1].created_date {
        // If created dates are identical, just verify both wallet units are present
        let names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
        assert!(names.contains(&&"first_wallet".to_string()));
        assert!(names.contains(&&"second_wallet".to_string()));
    } else {
        // Most recent created should come first in descending order
        assert_eq!(result.values[0].name, "second_wallet");
        assert_eq!(result.values[1].name, "first_wallet");
    }
}

#[tokio::test]
async fn test_sort_by_last_modified_after_updates() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create two wallet units
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "first_wallet".to_string();
    provider.create(wallet_unit1).await.unwrap();

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "second_wallet".to_string();
    provider.create(wallet_unit2).await.unwrap();

    // Small delay to ensure different last_modified
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Update the first wallet unit to change its last_modified
    let update_request = UpdateManagedInstanceRequest {
        status: Some(InstanceStatus::Revoked),
        ..Default::default()
    };
    provider
        .update(&wallet_unit_id1, update_request)
        .await
        .unwrap();

    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::LastModified,
            direction: Some(one_core::model::common::SortDirection::Descending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);
    // Most recently modified (updated) should come first
    assert_eq!(result.values[0].name, "first_wallet");
    assert_eq!(result.values[1].name, "second_wallet");
    assert!(result.values[0].last_modified > result.values[1].last_modified);
}

#[tokio::test]
async fn test_sort_with_pagination() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create 5 wallet units with alphabetical names
    let names = vec!["echo", "alpha", "delta", "bravo", "charlie"];
    for name in &names {
        let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
        let mut wallet_unit = dummy_managed_instance(wallet_unit_id, test_setup.organisation_id);
        wallet_unit.name = name.to_string();
        provider.create(wallet_unit).await.unwrap();
    }

    // Get first page (2 items) sorted by name ascending
    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 2,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 5);
    assert_eq!(result.total_pages.unwrap(), 3);
    assert_eq!(result.values.len(), 2);

    // First page should contain first 2 alphabetically
    let first_page_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(first_page_names, vec!["alpha", "bravo"]);

    // Get second page
    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 1,
            page_size: 2,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: None,
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 5);
    assert_eq!(result.total_pages.unwrap(), 3);
    assert_eq!(result.values.len(), 2);

    // Second page should contain next 2 alphabetically
    let second_page_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(second_page_names, vec!["charlie", "delta"]);
}

#[tokio::test]
async fn test_sort_with_filtering() {
    let test_setup = setup(0).await;
    let provider = test_setup.provider;

    // Create wallet units with different statuses and names
    let wallet_unit_id1: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit1 = dummy_managed_instance(wallet_unit_id1, test_setup.organisation_id);
    wallet_unit1.name = "zebra_active".to_string();
    wallet_unit1.status = InstanceStatus::Active;
    provider.create(wallet_unit1).await.unwrap();

    let wallet_unit_id2: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit2 = dummy_managed_instance(wallet_unit_id2, test_setup.organisation_id);
    wallet_unit2.name = "alpha_active".to_string();
    wallet_unit2.status = InstanceStatus::Active;
    provider.create(wallet_unit2).await.unwrap();

    let wallet_unit_id3: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_unit3 = dummy_managed_instance(wallet_unit_id3, test_setup.organisation_id);
    wallet_unit3.name = "beta_revoked".to_string();
    wallet_unit3.status = InstanceStatus::Revoked;
    provider.create(wallet_unit3).await.unwrap();

    // Query only ACTIVE wallet units, sorted by name ascending
    let query = ManagedInstanceListQuery {
        include_count: true,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableManagedInstanceColumn::Name,
            direction: Some(one_core::model::common::SortDirection::Ascending),
        }),
        filtering: Some(
            ManagedInstanceFilterValue::Status(vec![InstanceStatus::Active]).condition(),
        ),
        include: None,
    };

    let result = provider.get_list(query).await.unwrap();

    assert_eq!(result.total_items.unwrap(), 2);
    assert_eq!(result.values.len(), 2);

    // Should only return ACTIVE wallet units, sorted by name
    let returned_names: Vec<&String> = result.values.iter().map(|wu| &wu.name).collect();
    assert_eq!(returned_names, vec!["alpha_active", "zebra_active"]);

    // Verify all returned items are ACTIVE
    assert!(
        result
            .values
            .iter()
            .all(|wu| wu.status == InstanceStatus::Active)
    );
}
