use one_core::model::instance::InstanceStatus;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::managed_instances::TestWalletInstance;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_wallet_instance_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let wallet_unit = context
        .db
        .managed_instances
        .create(org, TestWalletInstance::default())
        .await;

    // WHEN
    let resp = context.api.managed_instances.get(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&wallet_unit.id);
    resp["name"].assert_eq(&wallet_unit.name);
    resp["os"].assert_eq(&wallet_unit.os);
    resp["version"].assert_eq(&wallet_unit.version);
    resp["status"].assert_eq(&String::from("ACTIVE"));
    resp["providerName"].assert_eq(&wallet_unit.provider);
    assert_eq!(resp["providerType"], "PROCIVIS_ONE");
    assert_eq!(resp["role"], "WALLET");
    assert!(resp["walletProviderType"].is_null());
    assert!(resp["walletProviderName"].is_null());
    resp["publicKey"].assert_eq(&wallet_unit.authentication_key_jwk);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp["lastIssuance"].is_string());
}

#[tokio::test]
async fn test_get_revoked_wallet_instance_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let wallet_unit = context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                status: Some(InstanceStatus::Revoked),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.managed_instances.get(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&wallet_unit.id);
    resp["name"].assert_eq(&wallet_unit.name);
    resp["os"].assert_eq(&wallet_unit.os);
    resp["status"].assert_eq(&String::from("REVOKED"));
    resp["providerName"].assert_eq(&wallet_unit.provider);
    resp["publicKey"].assert_eq(&wallet_unit.authentication_key_jwk);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp["lastIssuance"].is_string());
}

#[tokio::test]
async fn test_get_wallet_instance_user_sub_in_response() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let wallet_unit = context
        .db
        .managed_instances
        .create(
            org,
            TestWalletInstance {
                user_sub: Some("sub-alice".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.managed_instances.get(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["userSub"], "sub-alice");
}

#[tokio::test]
async fn test_get_wallet_instance_version_in_response() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let wallet_unit = context
        .db
        .managed_instances
        .create(
            org,
            TestWalletInstance {
                version: Some("v1".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.managed_instances.get(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["version"], "v1");
}

#[tokio::test]
async fn test_get_wallet_instance_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;
    let non_existent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context.api.managed_instances.get(&non_existent_id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}
