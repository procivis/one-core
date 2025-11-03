use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_unit::TestHolderWalletUnit;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_wallet_unit_holder_details_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let now = OffsetDateTime::now_utc();
    let key = context
        .db
        .keys
        .create(
            &org,
            TestingKeyParams {
                id: Some(Uuid::new_v4().into()),
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
            key.clone(),
            TestHolderWalletUnit {
                last_modified: Some(now),
                status: Some(WalletUnitStatus::Active),
                wallet_provider_type: Some(WalletProviderType::ProcivisOne),
                wallet_provider_name: Some("PROCIVIS_ONE".to_string()),
                wallet_provider_url: Some("https://wallet.provider".to_string()),
                provider_wallet_unit_id: Some(Uuid::new_v4().into()),
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_units
        .holder_get_wallet_unit_details(&wallet_unit.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&wallet_unit.id);
    resp["providerWalletUnitId"].assert_eq(&wallet_unit.provider_wallet_unit_id);
    resp["walletProviderUrl"].assert_eq(&wallet_unit.wallet_provider_url);
    resp["walletProviderType"].assert_eq(&String::from("PROCIVIS_ONE"));
    resp["walletProviderName"].assert_eq(&wallet_unit.wallet_provider_name);
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
        .holder_wallet_units
        .holder_get_wallet_unit_details(&Uuid::new_v4().into())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0296");
    assert_eq!(resp_json["message"], "Holder wallet unit not found");
}
