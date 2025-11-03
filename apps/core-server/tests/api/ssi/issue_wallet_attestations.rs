use one_core::model::history::HistoryAction;
use one_core::model::wallet_unit::{
    UpdateWalletUnitRequest, WalletUnitRelations, WalletUnitStatus,
};
use one_core::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRelations,
};
use one_core::proto::jwt::Jwt;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::service::wallet_provider::dto::KeyStorageSecurityLevel;
use serde_json::json;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::fixtures::assert_history_count;
use crate::fixtures::wallet_provider::{
    create_key_possession_proof, create_wallet_unit_attestation_issuer_identifier,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn test_issue_wallet_attestations_success() {
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

    let auth_key_pop =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    let waa_key_pair = Ecdsa.generate_key().unwrap();
    let waa_pop =
        create_key_possession_proof(&waa_key_pair, context.config.app.core_base_url.clone()).await;

    let wua_key_pair1 = Ecdsa.generate_key().unwrap();
    let wua_key_pair2 = Ecdsa.generate_key().unwrap();
    let wua_pop1 =
        create_key_possession_proof(&wua_key_pair1, context.config.app.core_base_url.clone()).await;
    let wua_pop2 =
        create_key_possession_proof(&wua_key_pair2, context.config.app.core_base_url.clone()).await;
    // when
    let resp = context
        .api
        .wallet_provider
        .issue_attestation(
            wallet_unit.id,
            &auth_key_pop,
            vec![waa_pop],
            vec![
                (wua_pop1, KeyStorageSecurityLevel::Moderate),
                (wua_pop2, KeyStorageSecurityLevel::Basic),
            ],
        )
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;

    assert!(resp_json["waa"].is_array());
    assert!(resp_json["wua"].is_array());

    let waa = Jwt::<()>::decompose_token(resp_json["waa"][0].as_str().unwrap());
    let Ok(waa_jwt) = waa else {
        panic!("attestation is not a valid JWT");
    };
    assert_eq!(
        waa_jwt.header.r#type.as_ref().unwrap(),
        "oauth-client-attestation+jwt"
    );
    assert!(waa_jwt.payload.proof_of_possession_key.is_some());

    let wua = Jwt::<serde_json::Value>::decompose_token(resp_json["wua"][0].as_str().unwrap());
    let Ok(wua_jwt) = wua else {
        panic!("attestation is not a valid JWT");
    };
    assert_eq!(
        wua_jwt.header.r#type.as_ref().unwrap(),
        "keyattestation+jwt"
    );
    assert!(wua_jwt.payload.proof_of_possession_key.is_none());
    assert!(wua_jwt.payload.custom["attested_keys"].is_array());
    // One Updated entry if at least one WAA is issued
    assert_history_count(&context, &wallet_unit.id.into(), HistoryAction::Updated, 1).await;
    // One Issued entry for every WUA
    assert_history_count(&context, &wallet_unit.id.into(), HistoryAction::Issued, 2).await;
}

#[tokio::test]
async fn test_issue_wallet_attestations_empty_success() {
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
    let auth_key_pop =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .issue_attestation(wallet_unit.id, &auth_key_pop, vec![], vec![])
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json, json!({}));
}

#[tokio::test]
async fn test_issue_wallet_attestations_failed_with_non_existing_wallet_unit() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let auth_key_pop =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    let waa_key_pair = Ecdsa.generate_key().unwrap();
    let waa_pop =
        create_key_possession_proof(&waa_key_pair, context.config.app.core_base_url.clone()).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .issue_attestation(Uuid::new_v4().into(), &auth_key_pop, vec![waa_pop], vec![])
        .await;

    // then
    assert_eq!(resp.status(), 404);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0259");
    assert_eq!(resp_json["message"], "Wallet unit not found");
}

#[tokio::test]
async fn test_issue_wallet_attestations_failed_with_revoked_wallet_unit() {
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
                status: Some(WalletUnitStatus::Revoked),
                ..Default::default()
            },
        )
        .await;

    let auth_key_pop =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .issue_attestation(wallet_unit.id, &auth_key_pop, vec![], vec![])
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0261");
    assert_eq!(resp_json["message"], "Wallet unit revoked");
}

#[tokio::test]
async fn test_issue_wua_only_success() {
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

    let auth_key_pop =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    let wua_key_pair1 = Ecdsa.generate_key().unwrap();
    let wua_pop1 =
        create_key_possession_proof(&wua_key_pair1, context.config.app.core_base_url.clone()).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .issue_attestation(
            wallet_unit.id,
            &auth_key_pop,
            vec![],
            vec![(wua_pop1, KeyStorageSecurityLevel::Moderate)],
        )
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;

    assert!(resp_json["waa"].is_null());
    assert!(resp_json["wua"].is_array());

    let wua = Jwt::<serde_json::Value>::decompose_token(resp_json["wua"][0].as_str().unwrap());
    let Ok(wua_jwt) = wua else {
        panic!("attestation is not a valid JWT");
    };
    assert_eq!(
        wua_jwt.header.r#type.as_ref().unwrap(),
        "keyattestation+jwt"
    );
    assert!(wua_jwt.payload.proof_of_possession_key.is_none());
    assert!(wua_jwt.payload.custom["attested_keys"].is_array());
    // One Issued entry for the WUA
    assert_history_count(&context, &wallet_unit.id.into(), HistoryAction::Issued, 1).await;
    let wallet_unit = context
        .db
        .wallet_units
        .get(
            wallet_unit.id,
            &WalletUnitRelations {
                attested_keys: Some(WalletUnitAttestedKeyRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(wallet_unit.attested_keys.unwrap().len(), 1);
}

#[tokio::test]
async fn test_issue_waa_only_with_existing_attested_keys_success() {
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
                public_key: Some(holder_public_jwk.clone()),
                ..Default::default()
            },
        )
        .await;
    let now = OffsetDateTime::now_utc();
    context
        .db
        .wallet_units
        .update(
            wallet_unit.id,
            UpdateWalletUnitRequest {
                attested_keys: Some(vec![WalletUnitAttestedKey {
                    id: Uuid::new_v4().into(),
                    wallet_unit_id: wallet_unit.id,
                    created_date: now,
                    last_modified: now,
                    expiration_date: now + Duration::days(30),
                    public_key_jwk: holder_public_jwk,
                    revocation_list_index: None,
                    revocation_list: None,
                }]),
                ..Default::default()
            },
        )
        .await;

    let auth_key_pop =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    let waa_key_pair = Ecdsa.generate_key().unwrap();
    let waa_pop =
        create_key_possession_proof(&waa_key_pair, context.config.app.core_base_url.clone()).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .issue_attestation(wallet_unit.id, &auth_key_pop, vec![waa_pop], vec![])
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;

    assert!(resp_json["waa"].is_array());
    assert!(resp_json["wua"].is_null());

    let waa = Jwt::<()>::decompose_token(resp_json["waa"][0].as_str().unwrap());
    let Ok(waa_jwt) = waa else {
        panic!("attestation is not a valid JWT");
    };
    assert_eq!(
        waa_jwt.header.r#type.as_ref().unwrap(),
        "oauth-client-attestation+jwt"
    );
    assert!(waa_jwt.payload.proof_of_possession_key.is_some());
    // One Updated entry for WAA
    assert_history_count(&context, &wallet_unit.id.into(), HistoryAction::Updated, 1).await;
    let wallet_unit = context
        .db
        .wallet_units
        .get(
            wallet_unit.id,
            &WalletUnitRelations {
                attested_keys: Some(WalletUnitAttestedKeyRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(wallet_unit.attested_keys.unwrap().len(), 1);
}
