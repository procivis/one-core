use one_core::model::instance::InstanceStatus;
use one_core::model::managed_instance::ManagedInstanceListQuery;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use similar_asserts::assert_eq;

use crate::fixtures::wallet_provider::{
    create_key_possession_proof, create_wallet_unit_attestation_issuer_identifier,
};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_register_wallet_unit_successfully_integrity_check_disabled() {
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
            params:
              public:
                walletInstanceAttestation:
                    integrityCheck:
                        enabled: false
    "}
    .to_string();
    // given
    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
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
        .register_wallet(
            "PROCIVIS_ONE",
            "ANDROID",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;

    assert!(resp_json["id"].as_str().is_some());

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert_eq!(wallet_unit.status, InstanceStatus::Active);
}

#[tokio::test]
async fn test_register_wallet_unit_successfully_integrity_check_enabled() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;
    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet("PROCIVIS_ONE", "ANDROID", None, None)
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;

    assert!(resp_json["id"].as_str().is_some());
    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    resp_json["nonce"].assert_eq(&wallet_unit.nonce);
    assert_eq!(wallet_unit.status, InstanceStatus::Pending);
    assert_eq!(wallet_unit.last_issuance, None);
    assert_eq!(wallet_unit.authentication_key_jwk, None);
}

#[tokio::test]
async fn test_register_wallet_unit_fail_integrity_check_disabled_no_proof_and_pubkey() {
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
            params:
              public:
                walletInstanceAttestation:
                    integrityCheck:
                        enabled: false
    "}
    .to_string();
    // given
    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet("PROCIVIS_ONE", "ANDROID", None, None)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0279");
}

#[tokio::test]
async fn test_register_wallet_unit_successfully_integrity_check_enabled_web() {
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
        .register_wallet(
            "PROCIVIS_ONE",
            "WEB",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;

    assert!(resp_json["id"].as_str().is_some());
    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert_eq!(wallet_unit.status, InstanceStatus::Active);
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
        .register_wallet(
            "PROCIVIS_ONE",
            "ANDROID",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0431");
}

#[tokio::test]
async fn test_register_wallet_unit_fail_on_duplicate_public_key() {
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
        .register_wallet(
            "PROCIVIS_ONE",
            "WEB",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;
    assert_eq!(resp.status(), 201);

    // duplicate registration
    let resp = context
        .api
        .wallet_provider
        .register_wallet(
            "PROCIVIS_ONE",
            "WEB",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0271");
}

#[tokio::test]
async fn test_register_wallet_unit_provider_no_org() {
    // given
    let (context, _) = TestContext::new_with_organisation(None).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet(
            "PROCIVIS_ONE",
            "WEB",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0286");
}

#[tokio::test]
async fn test_register_wallet_unit_with_user_authentication_nonce_path_returns_user_nonce() {
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
            params:
              public:
                userAuthentication:
                  required: true
                  identityProvider: https://idp.example.com
                  clientId: my-client
                  redirectUri: myapp://callback
                  tokenValidation:
                    aud: my-client
                    iss: https://idp.example.com
                    jwksUri: https://idp.example.com/.well-known/jwks.json
    "}
    .to_string();
    // given
    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet("PROCIVIS_ONE", "ANDROID", None, None)
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;

    assert!(resp_json["id"].as_str().is_some());
    assert!(resp_json["nonce"].as_str().is_some());
    assert!(resp_json["userNonce"].as_str().is_some());

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert_eq!(wallet_unit.status, InstanceStatus::Pending);
    resp_json["nonce"].assert_eq(&wallet_unit.nonce);
    resp_json["userNonce"].assert_eq(&wallet_unit.user_nonce);
}

#[tokio::test]
async fn test_register_wallet_unit_with_user_authentication_auth_key_path_returns_user_nonce() {
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
            params:
              public:
                walletInstanceAttestation:
                    integrityCheck:
                        enabled: false
                userAuthentication:
                  required: true
                  identityProvider: https://idp.example.com
                  clientId: my-client
                  redirectUri: myapp://callback
                  tokenValidation:
                    aud: my-client
                    iss: https://idp.example.com
                    jwksUri: https://idp.example.com/.well-known/jwks.json
    "}
    .to_string();
    // given
    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
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
        .register_wallet(
            "PROCIVIS_ONE",
            "ANDROID",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;

    assert!(resp_json["id"].as_str().is_some());
    assert!(resp_json["userNonce"].as_str().is_some());

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert_eq!(wallet_unit.status, InstanceStatus::Pending);
    resp_json["userNonce"].assert_eq(&wallet_unit.user_nonce);
}

#[tokio::test]
async fn test_register_wallet_unit_without_user_authentication_no_user_nonce() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet("PROCIVIS_ONE", "ANDROID", None, None)
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;

    assert!(resp_json["id"].as_str().is_some());
    assert!(resp_json["nonce"].as_str().is_some());
    assert_eq!(resp_json["userNonce"], serde_json::Value::Null);

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert!(wallet_unit.user_nonce.is_none());
}

fn user_authentication_config(required: bool) -> String {
    format!(
        indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
            params:
              public:
                userAuthentication:
                  required: {}
                  identityProvider: https://idp.example.com
                  clientId: my-client
                  redirectUri: myapp://callback
                  tokenValidation:
                    aud: my-client
                    iss: https://idp.example.com
                    jwksUri: https://idp.example.com/.well-known/jwks.json
    "},
        required
    )
}

// Web instances cannot run the user binding flow, so the user binding is skipped for them and the
// instance is active right after registration.
#[tokio::test]
async fn test_register_wallet_unit_web_skips_optional_user_authentication() {
    // given
    let (context, org) =
        TestContext::new_with_organisation(Some(user_authentication_config(false))).await;
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
        .register_wallet(
            "PROCIVIS_ONE",
            "WEB",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    assert!(resp_json["id"].as_str().is_some());
    assert_eq!(resp_json["nonce"], serde_json::Value::Null);
    assert_eq!(resp_json["userNonce"], serde_json::Value::Null);

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert_eq!(wallet_unit.status, InstanceStatus::Active);
    assert!(wallet_unit.user_nonce.is_none());
}

#[tokio::test]
async fn test_register_wallet_unit_web_fails_when_user_authentication_required() {
    // given
    let (context, org) =
        TestContext::new_with_organisation(Some(user_authentication_config(true))).await;
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
        .register_wallet(
            "PROCIVIS_ONE",
            "WEB",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0473");

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert!(wallet_units.values.is_empty());
}

#[tokio::test]
async fn test_register_wallet_unit_provider_org_disabled() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;
    context.db.organisations.deactivate(&org.id).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_wallet(
            "PROCIVIS_ONE",
            "WEB",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0284");
}
