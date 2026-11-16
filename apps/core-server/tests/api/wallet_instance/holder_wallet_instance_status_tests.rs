use one_core::model::instance::{InstanceRole, InstanceStatus, WalletProviderType};
use shared_types::{InstanceId, KeyId, ManagedInstanceId};
use similar_asserts::assert_eq;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;

#[tokio::test]
async fn test_holder_instance_status_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;
    let non_existent_id = InstanceId::new();

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_wallet_instance_status(&non_existent_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0296");
}

#[tokio::test]
async fn test_holder_instance_status_already_revoked() {
    // GIVEN - Wallet unit that's already revoked should return success without checking
    let (context, org) = TestContext::new_with_organisation(None).await;
    let now = one_core::clock::now_utc();

    let authentication_key = context
        .db
        .keys
        .create(
            &org,
            TestingKeyParams {
                id: Some(KeyId::new()),
                created_date: Some(now),
                last_modified: Some(now),
                name: Some("authentication_key".to_string()),
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(vec![0; 32]),
                key_reference: Some(vec![0; 32]),
            },
        )
        .await;

    // Create wallet unit with status already set to Revoked
    let wallet_unit = context
        .db
        .holder_wallet_units
        .create(
            org.clone(),
            Some(authentication_key.clone()),
            TestHolderWalletInstanceParams {
                status: Some(InstanceStatus::Revoked),
                provider_type: Some(WalletProviderType::ProcivisOne),
                provider_name: Some("PROCIVIS_ONE".to_string()),
                provider_url: Some("https://wallet.provider".to_string()),
                provider_wallet_unit_id: Some(ManagedInstanceId::new()),
                role: Some(InstanceRole::Wallet),
                user_nonce: None,
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_wallet_instance_status(&wallet_unit.id)
        .await;

    // THEN - should succeed without making any external calls
    assert_eq!(resp.status(), 204);

    // Verify wallet unit status remains Revoked
    let updated_wallet_unit = context.db.holder_wallet_units.get(wallet_unit.id).await;

    assert_eq!(updated_wallet_unit.status, InstanceStatus::Revoked);
}
