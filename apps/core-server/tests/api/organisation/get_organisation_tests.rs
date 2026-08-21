use one_core::model::instance::{InstanceRole, InstanceStatus, WalletProviderType};
use one_core::model::organisation::{OrganisationConfiguration, UpdateOrganisationRequest};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;
use crate::utils::field_match::FieldHelpers;

fn wallet_provider_metadata() -> serde_json::Value {
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
        "ecosystems": [ecosystem_metadata()]
    })
}

fn verifier_provider_metadata() -> serde_json::Value {
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
        "credentialSchemas": [],
        "ecosystems": [ecosystem_metadata()]
    })
}

fn ecosystem_metadata() -> serde_json::Value {
    json!({
        "name": "EUDI",
        "displayName": [{ "lang": "en", "value": "EUDI" }],
        "description": [{ "lang": "en", "value": "EUDI ecosystem" }],
        "logo": "data:image/png;base64,logo",
        "defaultSelected": true,
        "trustCollections": [],
        "credentialSchemas": [],
        "proofSchemas": []
    })
}

#[tokio::test]
async fn test_get_organisation_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp.get("parentOrganisation").is_none());
}

#[tokio::test]
async fn test_get_organisation_returns_parent_organisation() {
    // GIVEN
    let (context, parent) = TestContext::new_with_organisation(None).await;
    let child = context.db.organisations.create_with_parent(parent.id).await;

    // WHEN
    let resp = context.api.organisations.get(&child.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&child.id);
    resp["parentOrganisation"].assert_eq(&parent.id);
}

#[tokio::test]
async fn test_get_organisation_returns_wallet_instance() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let now = one_core::clock::now_utc();
    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                id: Some(Uuid::new_v4().into()),
                created_date: Some(now),
                last_modified: Some(now),
                name: Some("auth-key".to_string()),
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(vec![0; 32]),
                key_reference: Some(vec![0; 32]),
            },
        )
        .await;
    let mock_server = MockServer::builder().start().await;
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wallet_provider_metadata()))
        .expect(1)
        .mount(&mock_server)
        .await;

    let holder_wallet_instance = context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            Some(key.clone()),
            TestHolderWalletInstanceParams {
                status: Some(InstanceStatus::Active),
                provider_type: Some(WalletProviderType::ProcivisOne),
                provider_name: Some("PROCIVIS_ONE".to_string()),
                provider_url: Some(mock_server.uri()),
                provider_wallet_unit_id: Some(Uuid::new_v4().into()),
                role: Some(InstanceRole::Wallet),
                user_nonce: None,
            },
        )
        .await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&organisation.id);

    let wallet_instance = resp["walletInstance"].as_object().unwrap();
    assert_eq!(wallet_instance["providerUrl"], mock_server.uri());
    assert_eq!(wallet_instance["id"], holder_wallet_instance.id.to_string());
    assert_eq!(wallet_instance["providerName"], "PROCIVIS_ONE");
    assert_eq!(wallet_instance["authenticationKeyType"], "ECDSA");

    let feature_flags = wallet_instance["featureFlags"].as_object().unwrap();
    assert_eq!(feature_flags["ecosystemsEnabled"], true);
    assert_eq!(feature_flags["refreshCredentialBatchEnabled"], true);
    assert_eq!(feature_flags["documentSigningEnabled"], false);
    assert_eq!(feature_flags["ecosystemsEnforcementEnabled"], false);

    // the ecosystems advertised by the wallet provider, none of them selected yet
    let ecosystems = resp["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);
    assert_eq!(ecosystems[0]["name"], "EUDI");
    assert_eq!(ecosystems[0]["selected"], false);
    assert_eq!(ecosystems[0]["defaultSelected"], true);
    assert_eq!(ecosystems[0]["logo"], "data:image/png;base64,logo");

    let configuration = resp["configuration"].as_object().unwrap();
    assert!(!configuration.contains_key("selectedEcosystems"));
    assert_eq!(configuration["trustedRpRequired"], false);
    assert_eq!(configuration["trustedIssuerRequired"], false);
    assert_eq!(configuration["trustedWalletProviderRequired"], false);
    assert_eq!(configuration["enforceEcosystemAsIssuer"], false);
    assert_eq!(configuration["enforceEcosystemAsHolder"], false);
    assert_eq!(configuration["enforceEcosystemAsVerifier"], false);
}

#[tokio::test]
async fn test_get_organisation_without_wallet_instance_omits_field() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&organisation.id);
    assert!(resp.get("walletInstance").is_none());
}

#[tokio::test]
async fn get_deactivated_organisation_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    context.db.organisations.deactivate(&organisation.id).await;
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    assert!(resp["deactivatedAt"].is_string());
}

#[tokio::test]
async fn test_get_organisation_with_verifier_instance_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let now = one_core::clock::now_utc();
    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                id: Some(Uuid::new_v4().into()),
                created_date: Some(now),
                last_modified: Some(now),
                name: Some("auth-key".to_string()),
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(vec![0; 32]),
                key_reference: Some(vec![0; 32]),
            },
        )
        .await;
    let mock_server = MockServer::builder().start().await;
    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(verifier_provider_metadata()))
        .expect(1)
        .mount(&mock_server)
        .await;

    let verifier_instance = context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            Some(key),
            TestHolderWalletInstanceParams {
                role: Some(InstanceRole::Verifier),
                provider_url: Some(mock_server.uri()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&organisation.id);
    assert!(resp["createdDate"].is_string());
    assert!(resp["lastModified"].is_string());
    let verifier_instance_resp = resp["verifierInstance"].as_object().unwrap();
    assert_eq!(
        verifier_instance_resp["id"],
        verifier_instance.id.to_string()
    );
    assert_eq!(verifier_instance_resp["providerName"], "PROCIVIS_ONE");
    assert_eq!(verifier_instance_resp["providerUrl"], mock_server.uri());
    assert_eq!(verifier_instance_resp["authenticationKeyType"], "ECDSA");

    let feature_flags = verifier_instance_resp["featureFlags"].as_object().unwrap();
    assert_eq!(feature_flags["ecosystemsEnabled"], true);
    assert_eq!(feature_flags["accessCertificateProvisioningEnabled"], false);
    assert_eq!(feature_flags["ecosystemsEnforcementEnabled"], false);

    // the ecosystems advertised by the verifier provider
    let ecosystems = resp["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);
    assert_eq!(ecosystems[0]["name"], "EUDI");
    assert_eq!(ecosystems[0]["selected"], false);

    let configuration = resp["configuration"].as_object().unwrap();
    assert_eq!(configuration["trustedIssuerRequired"], false);
}

#[tokio::test]
async fn test_get_organisation_without_instance_returns_configured_ecosystems() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context
        .db
        .organisations
        .update(
            &organisation.id,
            UpdateOrganisationRequest {
                configuration: Some(OrganisationConfiguration {
                    selected_ecosystems: vec!["EUDI".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    // no instance is linked, so the ecosystems configured on this core are reported
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let ecosystems = resp["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);
    assert_eq!(ecosystems[0]["name"], "EUDI");
    assert_eq!(ecosystems[0]["selected"], true);
    assert_eq!(ecosystems[0]["description"][0]["value"], "EUDI ecosystem");
    assert!(!ecosystems[0]["logo"].as_str().unwrap().is_empty());
}
