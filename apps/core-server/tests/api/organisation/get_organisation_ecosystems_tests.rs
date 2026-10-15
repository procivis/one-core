use one_core::model::organisation::{OrganisationConfiguration, UpdateOrganisationRequest};
use serde_json::json;
use similar_asserts::assert_eq;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;

fn metadata_with_ecosystems() -> serde_json::Value {
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
        "ecosystems": [
            {
                "name": "EUDI",
                "displayName": [{ "lang": "en", "value": "EUDI" }],
                "description": [{ "lang": "en", "value": "EUDI ecosystem" }],
                "logo": "data:image/png;base64,logo",
                "defaultSelected": true,
                "trustCollections": [],
                "credentialSchemas": [],
                "proofSchemas": []
            },
            {
                // not configured on this core, must be filtered out
                "name": "UNKNOWN",
                "displayName": [],
                "description": [],
                "logo": "",
                "defaultSelected": false,
                "trustCollections": [],
                "credentialSchemas": [],
                "proofSchemas": []
            }
        ]
    })
}

#[tokio::test]
async fn test_get_organisation_ecosystems_without_instance_returns_configured_ecosystems() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context.api.organisations.get(&organisation.id).await;

    // THEN
    // no instance is linked, so the ecosystems configured on this core are reported
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let ecosystems = resp["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);
    assert_eq!(ecosystems[0]["name"], "EUDI");
    assert_eq!(ecosystems[0]["selected"], false);
    assert_eq!(ecosystems[0]["description"][0]["value"], "EUDI ecosystem");
    assert!(!ecosystems[0]["logo"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_organisation_ecosystems_filters_locally_unknown_ecosystems() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_with_ecosystems()))
        .expect(1)
        .mount(&mock_server)
        .await;

    context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            None,
            TestHolderWalletInstanceParams {
                provider_url: Some(mock_server.uri()),
                ..Default::default()
            },
        )
        .await;

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
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let ecosystems = resp["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);
    assert_eq!(ecosystems[0]["name"], "EUDI");
    assert_eq!(ecosystems[0]["selected"], true);
    assert_eq!(ecosystems[0]["logo"], "data:image/png;base64,logo");
    assert_eq!(ecosystems[0]["displayName"][0]["value"], "EUDI");
    assert_eq!(ecosystems[0]["description"][0]["value"], "EUDI ecosystem");
}

#[tokio::test]
async fn test_get_organisation_ecosystems_not_selected() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_with_ecosystems()))
        .expect(1)
        .mount(&mock_server)
        .await;

    context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            None,
            TestHolderWalletInstanceParams {
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
    let ecosystems = resp["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);
    assert_eq!(ecosystems[0]["name"], "EUDI");
    assert_eq!(ecosystems[0]["selected"], false);
}
