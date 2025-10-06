use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::wallet_unit::WalletUnitStatus;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::api_ssi_wallet_provider_tests::{
    create_key_possession_proof, create_wallet_unit_attestation_issuer_identifier,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn activate_wallet_unit_nonce_expired() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let nonce = "nonce-1234";
    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org.clone(),
            TestWalletUnit {
                public_key: Some(holder_public_jwk),
                status: Some(WalletUnitStatus::Pending),
                nonce: Some(nonce.to_string()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_wallet(wallet_unit.id, "dummy attestation", nonce)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0153");
    let wallet_unit = context
        .db
        .wallet_units
        .get(&wallet_unit.id, &Default::default())
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, WalletUnitStatus::Error);
}

#[tokio::test]
async fn activate_wallet_unit_attestation_invalid() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org.clone(),
            TestWalletUnit {
                public_key: None,
                status: Some(WalletUnitStatus::Pending),
                nonce: Some("nonce-1234".to_string()),
                last_modified: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_wallet(wallet_unit.id, "dummy attestation", &proof)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0266");
    let wallet_unit = context
        .db
        .wallet_units
        .get(&wallet_unit.id, &Default::default())
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, WalletUnitStatus::Error);

    let history = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit.id.into())
        .await;
    assert_eq!(history.total_items, 1);
    let history = &history.values[0];
    assert_eq!(history.entity_type, HistoryEntityType::WalletUnit);
    assert_eq!(history.action, HistoryAction::Errored);
    assert_eq!(history.organisation_id.unwrap(), org.id);
}

#[tokio::test]
async fn activate_wallet_unit_nonce_wrong_state() {
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
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_wallet(wallet_unit.id, "dummy attestation", "dummy proof")
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0265");
}

#[tokio::test]
async fn activate_wallet_unit_invalid_id() {
    // given
    let context = TestContext::new(None).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_wallet(Uuid::new_v4().into(), "dummy attestation", "dummy proof")
        .await;

    // then
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0259");
}
