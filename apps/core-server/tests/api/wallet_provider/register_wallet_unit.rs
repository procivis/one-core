use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::util::jwt::Jwt;
use similar_asserts::assert_eq;

use crate::api_ssi_wallet_provider_tests::{
    create_key_possession_proof, create_wallet_unit_attestation_issuer_identifier,
};
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_register_wallet_unit_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet("PROCIVIS_ONE", "ANDROID", &holder_public_jwk, &proof)
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
async fn test_register_wallet_unit_fail_on_disabled_wallet_provider() {
    // given
    let config_changes = indoc::indoc! {"
    walletProvider:
        PROCIVIS_ONE:
            enabled: false
    "}
    .to_string();
    let (context, org) = TestContext::new_with_organisation(Some(config_changes)).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet("PROCIVIS_ONE", "ANDROID", &holder_public_jwk, &proof)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0260");
    assert_eq!(
        resp_json["message"],
        "Wallet provider not enabled in config"
    );
}
