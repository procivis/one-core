use one_core::model::wallet_unit::WalletUnitStatus;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn test_list_wallet_unit_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    for i in 1..15 {
        let holder_key_pair = Ecdsa.generate_key().unwrap();
        let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();
        context
            .db
            .wallet_units
            .create(
                org.clone(),
                TestWalletUnit {
                    name: Some(format!("wallet_{i}")),
                    public_key: Some(holder_public_jwk),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN
    let resp = context.api.wallet_units.list().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["totalItems"], 14);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);
    assert!(values[0]["name"].is_string());
    assert!(values[0]["id"].is_string());
    assert!(values[0]["createdDate"].is_string());
    assert!(values[0]["lastModified"].is_string());
    assert!(values[0]["lastIssuance"].is_string());
    assert!(values[0]["os"].is_string());
    assert!(values[0]["status"].is_string());
    assert!(values[0]["walletProviderType"].is_string());
    assert!(values[0]["walletProviderName"].is_string());
    assert!(values[0]["publicKey"].is_string());
}

#[tokio::test]
async fn test_list_wallet_unit_revoked_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    for i in 1..10 {
        context
            .db
            .wallet_units
            .create(
                org.clone(),
                TestWalletUnit {
                    name: Some(format!("wallet_{i}")),
                    ..Default::default()
                },
            )
            .await;
    }

    for _i in 10..15 {
        context
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
    }

    // WHEN
    let resp = context.api.wallet_units.list().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["totalItems"], 14);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 14);

    // Check that we have both active and revoked wallet units
    let statuses: Vec<&str> = values
        .iter()
        .map(|v| v["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"ACTIVE"));
    assert!(statuses.contains(&"REVOKED"));
}

#[tokio::test]
async fn test_list_wallet_unit_empty_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.wallet_units.list().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalPages"], 0);
    assert_eq!(resp["totalItems"], 0);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values.len(), 0);
}
