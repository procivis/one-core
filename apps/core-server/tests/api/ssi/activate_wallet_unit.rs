use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::instance::{InstanceRole, InstanceStatus};
use one_core::model::managed_instance::ManagedInstanceOs;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use reqwest::header::AUTHORIZATION;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::wallet_provider::{
    create_key_possession_proof, create_verifier_provider_issuer_identifier,
    create_wallet_unit_attestation_issuer_identifier,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::managed_instances::TestWalletInstance;

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
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                public_key: Some(holder_public_jwk),
                status: Some(InstanceStatus::Pending),
                nonce: Some(nonce.to_string()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_wallet(wallet_unit.id, "dummy attestation", nonce, None)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0153");
    let wallet_unit = context
        .db
        .managed_instances
        .get(&wallet_unit.id)
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, InstanceStatus::Error);
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
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                public_key: None,
                status: Some(InstanceStatus::Pending),
                nonce: Some("nonce-1234".to_string()),
                last_modified: Some(one_core::clock::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_wallet(wallet_unit.id, "dummy attestation", &proof, None)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0266");
    let wallet_unit = context
        .db
        .managed_instances
        .get(&wallet_unit.id)
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, InstanceStatus::Error);

    let history = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit.id.into())
        .await;
    assert_eq!(history.total_items, 1);
    let history = &history.values[0];
    assert_eq!(history.entity_type, HistoryEntityType::ManagedInstance);
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
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                public_key: Some(holder_public_jwk),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_wallet(wallet_unit.id, "dummy attestation", "dummy proof", None)
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
        .activate_wallet(
            Uuid::new_v4().into(),
            "dummy attestation",
            "dummy proof",
            None,
        )
        .await;

    // then
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0259");
}

#[tokio::test]
async fn activate_wallet_unit_user_id_token_not_expected() {
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let nonce = "nonce-1234";
    let wallet_unit = context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                status: Some(InstanceStatus::Pending),
                nonce: Some(nonce.to_string()),
                ..Default::default()
            },
        )
        .await;

    let resp = context
        .api
        .wallet_provider
        .activate_wallet(
            wallet_unit.id,
            "dummy attestation",
            "dummy proof",
            Some("some.jwt.token"),
        )
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0446");
}

#[tokio::test]
async fn activate_wallet_unit_missing_required_user_id_token() {
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
    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let nonce = "nonce-1234";
    let wallet_unit = context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                status: Some(InstanceStatus::Pending),
                nonce: Some(nonce.to_string()),
                ..Default::default()
            },
        )
        .await;

    let resp = context
        .api
        .wallet_provider
        .activate_wallet(wallet_unit.id, "dummy attestation", "dummy proof", None)
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0447");
}

#[tokio::test]
async fn activate_instance_verifier_role_successfully() {
    // given: PROCIVIS_ONE verifierProvider config has no integrityCheck, so
    // activation goes through the no-integrity-check, self-certifying proof path.
    let config = indoc::indoc! {"
      verifierProvider:
        PROCIVIS_ONE:
          params:
            public:
              integrityCheck: null
    "};
    let (context, org) = TestContext::new_with_organisation(Some(config.to_string())).await;
    create_verifier_provider_issuer_identifier(&context, &org).await;

    let device_key_pair = Ecdsa.generate_key().unwrap();
    let device_public_jwk = device_key_pair.key.public_key_as_jwk().unwrap();
    let proof =
        create_key_possession_proof(&device_key_pair, context.config.app.core_base_url.clone())
            .await;

    let verifier_instance = context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                role: Some(InstanceRole::Verifier),
                status: Some(InstanceStatus::Pending),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_instance(
            verifier_instance.id,
            json!({ "attestationKeyProof": proof }),
        )
        .await;

    // then
    assert_eq!(resp.status(), 200);

    let updated = context
        .db
        .managed_instances
        .get(&verifier_instance.id)
        .await
        .unwrap();
    assert_eq!(updated.status, InstanceStatus::Active);
    assert_eq!(updated.authentication_key_jwk, Some(device_public_jwk));
}

#[tokio::test]
async fn activate_instance_verifier_role_provisions_access_certificate() {
    // given: a standalone mock server whose URL is known before the app config is built, since
    // `accessCertificateConfiguration.providerUrl` has to be baked into the static YAML config.
    let access_cert_provider = MockServer::start().await;
    let signature_id = Uuid::new_v4().into();
    Mock::given(method(Method::POST))
        .and(path("/provision"))
        .and(header(AUTHORIZATION, "Bearer test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessCertificate": "test-access-certificate",
            "signatureId": signature_id,
        })))
        .expect(1)
        .mount(&access_cert_provider)
        .await;

    let config = indoc::formatdoc! {"
      verifierProvider:
        PROCIVIS_ONE:
          params:
            public:
              accessCertificateConfiguration:
                providerUrl: \"{}/provision\"
                organisationId: \"{}\"
                relyingPartyPublicIdentifier: \"RP123\"
                relyingPartyNationalRegistry: \"NR123\"
                issuerId: \"{}\"
    ", access_cert_provider.uri(), Uuid::new_v4(), Uuid::new_v4()};

    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
    create_verifier_provider_issuer_identifier(&context, &org).await;

    let verifier_instance = context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                role: Some(InstanceRole::Verifier),
                status: Some(InstanceStatus::Pending),
                os: Some(ManagedInstanceOs::Web),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .activate_instance(
            verifier_instance.id,
            json!({
                "verifierAccessCertificateCsr": "dummy-csr",
                "userAccessToken": "test-access-token",
            }),
        )
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["accessCertificate"], "test-access-certificate");

    let updated = context
        .db
        .managed_instances
        .get(&verifier_instance.id)
        .await
        .unwrap();
    assert_eq!(updated.status, InstanceStatus::Active);
    assert_eq!(updated.verifier_csr, None);
    assert_eq!(updated.verifier_signature_ids, Some(vec![signature_id]));
}
