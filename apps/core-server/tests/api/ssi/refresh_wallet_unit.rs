use one_core::model::wallet_unit::WalletUnitStatus;
use one_core::proto::jwt::Jwt;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::wallet_provider::{
    create_key_possession_proof, create_wallet_unit_attestation_issuer_identifier,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn test_refresh_wallet_unit_successfully() {
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

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .refresh_wallet(wallet_unit.id, proof)
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;

    assert!(resp_json["id"].as_str().is_some());

    let attestation = Jwt::<()>::decompose_token(resp_json["attestation"].as_str().unwrap());
    let Ok(attestation_jwt) = attestation else {
        panic!("attestation is not a valid JWT");
    };
    assert_eq!(
        attestation_jwt.header.r#type.as_ref().unwrap(),
        "oauth-client-attestation+jwt"
    );
    assert!(attestation_jwt.payload.proof_of_possession_key.is_some());
}

#[tokio::test]
async fn test_refresh_wallet_unit_failed_with_non_existing_wallet_unit() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .refresh_wallet(Uuid::new_v4().into(), proof)
        .await;

    // then
    assert_eq!(resp.status(), 404);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0259");
    assert_eq!(resp_json["message"], "Wallet unit not found");
}

#[tokio::test]
async fn test_refresh_wallet_unit_failed_with_revoked_wallet_unit() {
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

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .refresh_wallet(wallet_unit.id, proof)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0261");
    assert_eq!(resp_json["message"], "Wallet unit revoked");
}

#[tokio::test]
async fn test_refresh_wallet_unit_failed_with_refresh_before_minimum_refresh_time() {
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
            params:
              public:
                integrityCheck:
                    enabled: false
    "}
    .to_string();
    // given
    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let now = OffsetDateTime::now_utc();
    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org.clone(),
            TestWalletUnit {
                public_key: Some(holder_public_jwk),
                last_issuance: Some(Some(now)),
                ..Default::default()
            },
        )
        .await;

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .refresh_wallet(wallet_unit.id, proof)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0258");
    assert_eq!(resp_json["message"], "Minimum refresh time not reached");
}
