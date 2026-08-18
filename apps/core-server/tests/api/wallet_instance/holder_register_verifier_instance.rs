use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::holder_register_wallet_instance::metadata_without_user_auth;
use crate::utils::api_clients::holder_wallet_instance::TestHolderRegisterRequest;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

fn verifier_metadata() -> serde_json::Value {
    json!({
        "name": "PROCIVIS_ONE",
        "verifierAppAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
        },
        "featureFlags": {
            "ecosystemsEnabled": true,
            "accessCertificateProvisioningEnabled": false
        },
        "trustCollections": [],
        "proofSchemas": [],
        "credentialSchemas": []
    })
}

#[tokio::test]
async fn holder_register_verifier_instance_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(verifier_metadata()))
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
            role: Some("VERIFIER".to_string()),
            wallet_provider_url: Some(format!(
                "{}/ssi/verifier-provider/v1/PROCIVIS_ONE",
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
    let instance_id = resp["id"].parse::<Uuid>();

    let detail = context
        .api
        .holder_wallet_instances
        .holder_get_wallet_instance_details(&instance_id.into())
        .await;
    assert_eq!(detail.status(), 200);
    let detail = detail.json_value().await;
    assert_eq!(detail["role"], "VERIFIER");
    assert_eq!(detail["providerName"], "PROCIVIS_ONE");
}

#[tokio::test]
async fn holder_register_wallet_and_verifier_instance_in_same_organisation() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(verifier_metadata()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/instance/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    // WHEN
    let wallet_resp = context
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
    let verifier_resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            role: Some("VERIFIER".to_string()),
            wallet_provider_url: Some(format!(
                "{}/ssi/verifier-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(wallet_resp.status(), 201);
    assert_eq!(verifier_resp.status(), 201);
    let wallet_resp = wallet_resp.json_value().await;
    let verifier_resp = verifier_resp.json_value().await;

    let org_detail = context.api.organisations.get(&org.id).await;
    assert_eq!(org_detail.status(), 200);
    let org_detail = org_detail.json_value().await;
    assert_eq!(org_detail["verifierInstance"]["id"], verifier_resp["id"]);
    assert_eq!(org_detail["walletInstance"]["id"], wallet_resp["id"]);
}

#[tokio::test]
async fn holder_register_verifier_instance_already_exists() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(verifier_metadata()))
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

    let register = TestHolderRegisterRequest {
        organization_id: Some(org.id),
        role: Some("VERIFIER".to_string()),
        wallet_provider_url: Some(format!(
            "{}/ssi/verifier-provider/v1/PROCIVIS_ONE",
            mock_server.uri()
        )),
        key_type: Some("ECDSA".to_string()),
        ..Default::default()
    };
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(register.clone())
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN - registering a second verifier instance for the same organisation
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(register)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}
