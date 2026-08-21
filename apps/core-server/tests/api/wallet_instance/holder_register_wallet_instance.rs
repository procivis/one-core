use one_core::model::instance::InstanceStatus;
use one_core::model::organisation::{OrganisationConfiguration, UpdateOrganisationRequest};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::api_clients::holder_wallet_instance::{
    TestHolderActivateRequest, TestHolderRegisterRequest,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;
use crate::utils::field_match::FieldHelpers;

pub(super) fn metadata_without_user_auth() -> serde_json::Value {
    json!({
        "name": "PROCIVIS_ONE",
        "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
        },
        "featureFlags": {
            "ecosystemsEnabled": true,
            "refreshCredentialBatchEnabled": true
        },
        "trustCollections": []
    })
}

fn metadata_with_user_auth() -> serde_json::Value {
    json!({
        "name": "PROCIVIS_ONE",
        "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
        },
        "featureFlags": {
            "ecosystemsEnabled": true,
            "refreshCredentialBatchEnabled": true
        },
        "trustCollections": [],
        "userAuthentication": {
            "required": true,
            "identityProvider": "https://idp.example.com",
            "clientId": "wallet-client",
            "redirectUri": "https://wallet.example.com/callback",
            "tokenValidation": {
                "aud": "wallet-client",
                "iss": "https://idp.example.com",
                "jwksUri": "https://idp.example.com/.well-known/jwks.json"
            }
        }
    })
}

fn metadata_with_optional_user_auth() -> serde_json::Value {
    json!({
        "name": "PROCIVIS_ONE",
        "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
        },
        "featureFlags": {
            "ecosystemsEnabled": true,
            "refreshCredentialBatchEnabled": true
        },
        "trustCollections": [],
        "userAuthentication": {
            "required": false,
            "identityProvider": "https://idp.example.com",
            "clientId": "wallet-client",
            "redirectUri": "https://wallet.example.com/callback",
            "tokenValidation": {
                "aud": "wallet-client",
                "iss": "https://idp.example.com",
                "jwksUri": "https://idp.example.com/.well-known/jwks.json"
            }
        }
    })
}

#[tokio::test]
async fn holder_register_wallet_unit_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    // the organisation detail reports the ecosystems of the wallet provider too, but
    // reuses the metadata cached during the registration
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/instance/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["status"], "ACTIVE");
    assert!(resp["userNonce"].is_null());
    let history = context
        .db
        .histories
        .get_by_entity_id(&resp["id"].parse())
        .await;
    assert!(!history.values.is_empty());

    let org_detail = context.api.organisations.get(&org.id).await;
    assert_eq!(org_detail.status(), 200);
    let org_detail = org_detail.json_value().await;
    assert!(
        !org_detail
            .as_object()
            .unwrap()
            .contains_key("verifierInstance")
    );
    assert_eq!(org_detail["walletInstance"]["id"], resp["id"]);
}

#[tokio::test]
async fn holder_register_wallet_unit_with_optional_user_auth_is_active_on_web() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_with_optional_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    // the wallet provider skips the user binding for web instances as well, so no user nonce
    Mock::given(method(Method::POST))
        .and(path("/ssi/instance/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // activate endpoint must NOT be called
    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/instance/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["status"], "ACTIVE");
    assert!(resp["userNonce"].is_null());

    let detail = context
        .api
        .holder_wallet_instances
        .holder_get_wallet_instance_details(&resp["id"].parse())
        .await;
    assert_eq!(detail.status(), 200);
    assert_eq!(detail.json_value().await["status"], "ACTIVE");
}

#[tokio::test]
async fn holder_register_wallet_unit_with_required_user_auth_fails_on_web() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_with_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    // registration must not even be attempted against the wallet provider
    Mock::given(method(Method::POST))
        .and(path("/ssi/instance/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
            "userNonce": "user-nonce-abc123",
        })))
        .expect(0)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.json_value().await["code"], "BR_0473");
}

/// Creates a wallet instance that is pending user binding. Registration cannot produce such an
/// instance in this test setup (the holder resolves to the WEB os, which skips user binding), so
/// the state a mobile holder would be in is set up directly.
async fn pending_wallet_instance_with_user_auth(
    context: &crate::utils::context::TestContext,
    org: &one_core::model::organisation::Organisation,
    mock_server: &wiremock::MockServer,
    metadata: serde_json::Value,
) -> shared_types::InstanceId {
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock_server)
        .await;

    context
        .db
        .holder_wallet_units
        .create(
            org.clone(),
            None,
            TestHolderWalletInstanceParams {
                status: Some(InstanceStatus::Pending),
                provider_url: Some(mock_server.uri()),
                user_nonce: Some("user-nonce-abc123".to_string()),
                ..Default::default()
            },
        )
        .await
        .id
}

#[tokio::test]
async fn holder_activate_wallet_unit_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id = pending_wallet_instance_with_user_auth(
        &context,
        &org,
        &mock_server,
        metadata_with_user_auth(),
    )
    .await;

    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/instance/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: Some("my-jwt-token".to_string()),
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json_value().await, json!({}));
}

#[tokio::test]
async fn holder_activate_wallet_unit_without_user_auth_returns_error() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    // Register WITHOUT user_authentication configured
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/instance/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .mount(&mock_server)
        .await;

    let register_resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;
    assert_eq!(register_resp.status(), 201);
    let wallet_unit_id: shared_types::InstanceId = register_resp.json_value().await["id"].parse();

    // metadata mock for activate call (same endpoint, returns without userAuthentication)
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(&wallet_unit_id, TestHolderActivateRequest::default())
        .await;

    // THEN - wallet unit is Active (not Pending), so activation is rejected before user-auth check
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0450");
}

#[tokio::test]
async fn holder_activate_wallet_unit_not_found_returns_404() {
    // GIVEN
    let context = TestContext::new(None).await;
    let non_existent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &non_existent_id.into(),
            TestHolderActivateRequest::default(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn holder_activate_wallet_unit_passes_user_id_token_to_provider() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id = pending_wallet_instance_with_user_auth(
        &context,
        &org,
        &mock_server,
        metadata_with_user_auth(),
    )
    .await;

    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/instance/v1/.*/activate",
        ))
        .and(wiremock::matchers::body_partial_json(json!({
            "userIdToken": "user-jwt-token-xyz"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: Some("user-jwt-token-xyz".to_string()),
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json_value().await, json!({}));
}

#[tokio::test]
async fn holder_activate_wallet_unit_optional_auth_skips_sign_in() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id = pending_wallet_instance_with_user_auth(
        &context,
        &org,
        &mock_server,
        metadata_with_optional_user_auth(),
    )
    .await;

    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/instance/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN - user skips sign-in (no id token) and authentication is optional
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json_value().await, json!({}));
}

#[tokio::test]
async fn holder_activate_wallet_unit_required_auth_missing_token_fails_early() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id = pending_wallet_instance_with_user_auth(
        &context,
        &org,
        &mock_server,
        metadata_with_user_auth(),
    )
    .await;

    // activate endpoint must NOT be called when the required token is missing
    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/instance/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    // WHEN - authentication is required but no id token is supplied
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0454");
}

#[tokio::test]
async fn holder_activate_wallet_unit_expired_nonce_marks_error_and_signals_restart() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id = pending_wallet_instance_with_user_auth(
        &context,
        &org,
        &mock_server,
        metadata_with_user_auth(),
    )
    .await;

    // The wallet provider rejects activation because the registration nonce has expired (BR_0153).
    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/instance/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "code": "BR_0153" })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: Some("my-jwt-token".to_string()),
            },
        )
        .await;

    // THEN - activation fails with the "restart registration" error
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0455");

    // AND - the instance is marked failed (out of PENDING) so a retry can't re-hit the dead nonce
    let detail = context
        .api
        .holder_wallet_instances
        .holder_get_wallet_instance_details(&wallet_unit_id)
        .await;
    assert_eq!(detail.status(), 200);
    let detail = detail.json_value().await;
    assert_eq!(detail["status"], "ERROR");
}

#[tokio::test]
async fn holder_register_wallet_unit_succeeds_when_existing_wallet_unit_failed() {
    // GIVEN - the organisation already has a failed (Error) wallet unit from a previous,
    // aborted registration
    let (context, org) = TestContext::new_with_organisation(None).await;

    context
        .db
        .holder_wallet_units
        .create(
            org.clone(),
            None,
            TestHolderWalletInstanceParams {
                status: Some(InstanceStatus::Error),
                ..Default::default()
            },
        )
        .await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/instance/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN - the holder restarts registration
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN - registration is not blocked by the existing failed wallet unit
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["status"], "ACTIVE");
}

/// The metadata this core serves must be understood by the client this core
/// uses to consume it, so serve the real response of the wallet provider
/// endpoint.
#[tokio::test]
async fn holder_register_wallet_unit_accepts_metadata_served_by_this_core() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // an organisation with a selected ecosystem, so the metadata advertises one
    context
        .db
        .organisations
        .update(
            &org.id,
            UpdateOrganisationRequest {
                wallet_provider: Some(Some("PROCIVIS_ONE".to_string())),
                configuration: Some(OrganisationConfiguration {
                    selected_ecosystems: vec!["EUDI".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;

    let metadata = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await
        .json_value()
        .await;
    assert_eq!(metadata["ecosystems"].as_array().unwrap().len(), 1);

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/instance/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}
