use one_core::model::wallet_unit::WalletUnitStatus;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_units::TestWalletUnit;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_wallet_unit_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let wallet_unit = context
        .db
        .wallet_units
        .create(org, TestWalletUnit::default())
        .await;

    // WHEN
    let resp = context.api.wallet_units.get(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&wallet_unit.id);
    resp["name"].assert_eq(&wallet_unit.name);
    resp["os"].assert_eq(&wallet_unit.os);
    resp["status"].assert_eq(&String::from("ACTIVE"));
    resp["walletProviderType"].assert_eq(&String::from("PROCIVIS_ONE"));
    resp["walletProviderName"].assert_eq(&wallet_unit.wallet_provider_name);
    resp["publicKey"].assert_eq(&wallet_unit.public_key);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp["lastIssuance"].is_string());
}

#[tokio::test]
async fn test_get_revoked_wallet_unit_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org.clone(),
            TestWalletUnit {
                status: Some(WalletUnitStatus::Revoked),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.wallet_units.get(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&wallet_unit.id);
    resp["name"].assert_eq(&wallet_unit.name);
    resp["os"].assert_eq(&wallet_unit.os);
    resp["status"].assert_eq(&String::from("REVOKED"));
    resp["walletProviderType"].assert_eq(&String::from("PROCIVIS_ONE"));
    resp["walletProviderName"].assert_eq(&wallet_unit.wallet_provider_name);
    resp["publicKey"].assert_eq(&wallet_unit.public_key);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp["lastIssuance"].is_string());
}

#[tokio::test]
async fn test_get_wallet_unit_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;
    let non_existent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context.api.wallet_units.get(&non_existent_id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}
