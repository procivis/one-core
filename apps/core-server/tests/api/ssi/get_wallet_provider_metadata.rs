use one_core::model::organisation::{OrganisationConfiguration, UpdateOrganisationRequest};
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;

#[tokio::test]
async fn test_wallet_provider_metadata_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let mut resp = resp.json_value().await;
    let document_signers = resp
        .as_object_mut()
        .unwrap()
        .remove("documentSigners")
        .unwrap();
    let ecosystems = resp.as_object_mut().unwrap().remove("ecosystems").unwrap();
    assert_eq!(
        resp,
        serde_json::json!({
            "walletUnitAttestation": {
                "appIntegrityCheckRequired": true,
                "enabled": true,
                "required": false
            },
            "name":"PROCIVIS_ONE",
            "appVersion": {
                "minimum":"v1.50.0"
            },
            "featureFlags": {
              "trustEcosystemsEnabled": true,
              "ecosystemsEnabled": true,
              "refreshCredentialBatchEnabled": true,
              "documentSigningEnabled": true,
              "ecosystemsEnforcementEnabled": false
            },
            "trustCollections": []
        })
    );
    assert_eq!(document_signers.as_array().unwrap().len(), 1);
    assert_eq!(document_signers[0]["name"], serde_json::json!("SIGN8"));
    // no organisation is assigned to the provider, so no ecosystems are advertised
    assert_eq!(ecosystems, serde_json::json!([]));
}

#[tokio::test]
async fn test_wallet_provider_metadata_success_all_fields() {
    // GIVEN
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
          params:
            public:
              walletRegistration: DISABLED
              walletInstanceAttestation:
                integrityCheck:
                  enabled: false
              appVersion:
                minimum: v1.50.0
                minimumRecommended: v.1.20.0
                reject:
                    - v1.10.0
                    - v1.11.0
                updateScreen:
                  link: https://example.com
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let mut resp = resp.json_value().await;
    let document_signers = resp
        .as_object_mut()
        .unwrap()
        .remove("documentSigners")
        .unwrap();
    let ecosystems = resp.as_object_mut().unwrap().remove("ecosystems").unwrap();
    assert_eq!(
        resp,
        serde_json::json!({
            "walletUnitAttestation": {
                "appIntegrityCheckRequired": false,
                "enabled": false,
                "required": false
            },
            "name":"PROCIVIS_ONE",
            "appVersion": {
                "minimum":"v1.50.0",
                "minimumRecommended": "v.1.20.0",
                "reject": ["v1.10.0", "v1.11.0"],
                "updateScreen": {
                    "link": "https://example.com"
                }
            },
            "featureFlags": {
              "trustEcosystemsEnabled": true,
              "ecosystemsEnabled": true,
              "refreshCredentialBatchEnabled": true,
              "documentSigningEnabled": true,
              "ecosystemsEnforcementEnabled": false
            },
            "trustCollections": []
        })
    );
    assert_eq!(document_signers.as_array().unwrap().len(), 1);
    assert_eq!(document_signers[0]["name"], serde_json::json!("SIGN8"));
    // no organisation is assigned to the provider, so no ecosystems are advertised
    assert_eq!(ecosystems, serde_json::json!([]));
}

#[tokio::test]
async fn test_wallet_provider_metadata_with_user_authentication() {
    // GIVEN
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
          params:
            public:
              userAuthentication:
                required: true
                identityProvider: https://idp.example.com/realm/test
                clientId: my-client
                redirectUri: myapp://callback
                tokenValidation:
                  aud: my-client
                  iss: https://idp.example.com/realm/test
                  jwksUri: https://idp.example.com/realm/test/protocol/openid-connect/certs
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(
        resp["userAuthentication"],
        serde_json::json!({
            "required": true,
            "identityProvider": "https://idp.example.com/realm/test",
            "clientId": "my-client",
            "redirectUri": "myapp://callback",
            "tokenValidation": {
                "aud": "my-client",
                "iss": "https://idp.example.com/realm/test",
                "jwksUri": "https://idp.example.com/realm/test/protocol/openid-connect/certs"
            }
        })
    );
}

#[tokio::test]
async fn test_wallet_provider_metadata_without_user_authentication() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["userAuthentication"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_wallet_provider_metadata_fails_disabled_wallet_provider() {
    // GIVEN
    let config = indoc::indoc! {"
      app:
        enableWalletProvider: false
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let mut resp = resp.json_value().await;
    let document_signers = resp
        .as_object_mut()
        .unwrap()
        .remove("documentSigners")
        .unwrap();
    let ecosystems = resp.as_object_mut().unwrap().remove("ecosystems").unwrap();
    assert_eq!(
        resp,
        serde_json::json!({
            "walletUnitAttestation": {
                "appIntegrityCheckRequired": true,
                "enabled": true,
                "required": false
            },
            "name":"PROCIVIS_ONE",
            "appVersion": {
                "minimum":"v1.50.0"
            },
            "featureFlags": {
              "trustEcosystemsEnabled": true,
              "ecosystemsEnabled": true,
              "refreshCredentialBatchEnabled": true,
              "documentSigningEnabled": true,
              "ecosystemsEnforcementEnabled": false
            },
            "trustCollections": []
        })
    );
    assert_eq!(document_signers.as_array().unwrap().len(), 1);
    assert_eq!(document_signers[0]["name"], serde_json::json!("SIGN8"));
    // no organisation is assigned to the provider, so no ecosystems are advertised
    assert_eq!(ecosystems, serde_json::json!([]));
}

#[tokio::test]
async fn test_wallet_provider_metadata_fails_unknown_wallet_provider() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("UNKNOWN_WALLET_PROVIDER")
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_wallet_provider_metadata_with_ecosystems() {
    // GIVEN
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
          params:
            public:
              featureFlags:
                ecosystemsEnforcementEnabled: true
      ecosystem:
        EUDI:
          params:
            public:
              instanceProviderDefaultSelected: true
    "}
    .to_string();
    let (context, organisation) = TestContext::new_with_organisation(Some(config)).await;

    context
        .db
        .organisations
        .update(
            &organisation.id,
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

    let collection = context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                name: Some("EUDI collection".to_string()),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .credential_schemas
        .create(
            "ecosystem schema",
            &organisation,
            TestingCreateSchemaParams {
                ecosystem: Some("EUDI".into()),
                imported_source_url: Some("https://schemas.example.com/pid".to_string()),
                ..Default::default()
            },
        )
        .await;

    // a schema outside of any ecosystem is not advertised
    context
        .db
        .credential_schemas
        .create(
            "other schema",
            &organisation,
            TestingCreateSchemaParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["featureFlags"]["ecosystemsEnforcementEnabled"], true);

    let ecosystems = resp["ecosystems"].as_array().unwrap();
    assert_eq!(ecosystems.len(), 1);

    let ecosystem = &ecosystems[0];
    assert_eq!(ecosystem["name"], "EUDI");
    assert_eq!(
        ecosystem["description"],
        serde_json::json!([{"lang": "en", "value": "EUDI ecosystem"}])
    );
    assert!(ecosystem["logo"].as_str().is_some_and(|l| !l.is_empty()));
    assert_eq!(ecosystem["defaultSelected"], true);
    assert_eq!(
        ecosystem["trustCollections"],
        serde_json::json!([{"id": collection.id, "name": "EUDI collection"}])
    );
    assert_eq!(
        ecosystem["credentialSchemas"],
        serde_json::json!(["https://schemas.example.com/pid"])
    );

    // the deprecated flat list mirrors the collections of the advertised ecosystems
    let trust_collections = resp["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 1);
    assert_eq!(trust_collections[0]["id"], serde_json::json!(collection.id));
    assert_eq!(trust_collections[0]["name"], "EUDI collection");
    assert_eq!(trust_collections[0]["logo"], ecosystem["logo"]);
    assert_eq!(trust_collections[0]["defaultSelected"], true);
}

#[tokio::test]
async fn test_wallet_provider_metadata_ecosystems_include_inherited_trust_collections() {
    // GIVEN
    let (context, parent_organisation) = TestContext::new_with_organisation(None).await;
    let organisation = context
        .db
        .organisations
        .create_with_parent(parent_organisation.id)
        .await;

    context
        .db
        .organisations
        .update(
            &organisation.id,
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

    // the collection belongs to the parent organisation
    let collection = context
        .db
        .trust_collections
        .create(
            parent_organisation,
            TestTrustCollectionParams {
                name: Some("inherited collection".to_string()),
                ecosystem: Some("EUDI".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["ecosystems"][0]["trustCollections"],
        serde_json::json!([{"id": collection.id, "name": "inherited collection"}])
    );
}
