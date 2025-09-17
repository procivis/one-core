use one_core::model::wallet_unit::WalletUnitStatus;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;

use crate::api_ssi_wallet_provider_tests::create_wallet_unit_attestation_issuer_identifier;
use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn test_remove_wallet_unit_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org.clone(),
            TestWalletUnit {
                public_key: Some(holder_public_jwk),
                status: Some(WalletUnitStatus::Pending),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .delete_wallet_unit(wallet_unit.id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 204);

    let updated_wallet_unit = context
        .db
        .wallet_units
        .get(wallet_unit.id, &Default::default())
        .await;
    similar_asserts::assert_eq!(updated_wallet_unit, None);

    let history_entries = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit.id.into())
        .await;
    similar_asserts::assert_eq!(history_entries.values.len(), 0);
}

#[tokio::test]
async fn test_remove_wallet_fails_when_status_is_not_pending() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org.clone(),
            TestWalletUnit {
                public_key: Some(holder_public_jwk),
                status: Some(WalletUnitStatus::Active),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .delete_wallet_unit(wallet_unit.id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    similar_asserts::assert_eq!(resp_json["code"], "BR_0168");
}
