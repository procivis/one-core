use one_core::model::instance::{InstanceStatus, WalletProviderType};
use shared_types::{InstanceId, KeyId, ManagedInstanceId};
use similar_asserts::assert_eq;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_wallet_unit_holder_details_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let now = one_core::clock::now_utc();
    let key = context
        .db
        .keys
        .create(
            &org,
            TestingKeyParams {
                id: Some(KeyId::new()),
                created_date: Some(now),
                last_modified: Some(now),
                name: Some("test".to_string()),
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(vec![0; 32]),
                key_reference: Some(vec![0; 32]),
            },
        )
        .await;
    let wallet_unit = context
        .db
        .holder_wallet_units
        .create(
            org,
            Some(key.clone()),
            TestHolderWalletInstanceParams {
                status: Some(InstanceStatus::Active),
                provider_type: Some(WalletProviderType::ProcivisOne),
                provider_name: Some("PROCIVIS_ONE".to_string()),
                provider_url: Some("https://wallet.provider".to_string()),
                provider_wallet_unit_id: Some(ManagedInstanceId::new()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_get_wallet_instance_details(&wallet_unit.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&wallet_unit.id);
    resp["role"].assert_eq(&String::from("WALLET"));
    resp["providerInstanceId"].assert_eq(&wallet_unit.provider_instance_id);
    resp["providerUrl"].assert_eq(&wallet_unit.provider_url);
    resp["providerType"].assert_eq(&String::from("PROCIVIS_ONE"));
    resp["providerName"].assert_eq(&wallet_unit.provider_name);
    resp["status"].assert_eq(&String::from("ACTIVE"));
    assert!(resp["lastModified"].is_string());
    assert!(resp["createdDate"].is_string());

    let authentication_key = resp["authenticationKey"].as_object().unwrap();

    authentication_key["id"].assert_eq(&key.id);
    authentication_key["name"].assert_eq(&key.name);
    authentication_key["keyType"].assert_eq(&key.key_type);
    authentication_key["storageType"].assert_eq(&key.storage_type.to_string());
    assert!(authentication_key["createdDate"].is_string());
    assert!(authentication_key["lastModified"].is_string());
}

#[tokio::test]
async fn test_get_wallet_unit_holder_details_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_get_wallet_instance_details(&InstanceId::new())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0296");
}
