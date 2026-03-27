use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
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
    let resp = resp.json_value().await;
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
              "trustEcosystemsEnabled": true
            },
            "trustCollections": []
        })
    );
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
    let resp = resp.json_value().await;
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
              "trustEcosystemsEnabled": true
            },
            "trustCollections": []
        })
    );
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
    let resp = resp.json_value().await;
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
              "trustEcosystemsEnabled": true
            },
            "trustCollections": []
        })
    );
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
async fn test_wallet_provider_metadata_with_trust_collections() {
    // GIVEN
    let collection_1_id = Uuid::new_v4().into();
    let collection_2_id = Uuid::new_v4().into();

    let config = indoc::formatdoc! {"
      walletProvider:
        PROCIVIS_ONE:
          params:
            public:
              trustCollections:
                {collection_1_id}:
                  logo: logo1
                  displayName:
                    en: name1
                  description:
                    en: description1
                {collection_2_id}:
                  logo: logo2
                  displayName:
                    en: name2
                  description:
                    en: description2
    "};
    let (context, organisation) = TestContext::new_with_organisation(Some(config)).await;

    let collection_1 = context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                id: Some(collection_1_id),
                name: Some("collection1".to_string()),
                ..Default::default()
            },
        )
        .await;

    let collection_2 = context
        .db
        .trust_collections
        .create(
            organisation,
            TestTrustCollectionParams {
                id: Some(collection_2_id),
                name: Some("collection2".to_string()),
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
        resp["walletUnitAttestation"],
        serde_json::json!( {
            "appIntegrityCheckRequired": true,
            "enabled": true,
            "required": false
        })
    );
    assert_eq!(resp["name"], serde_json::json!("PROCIVIS_ONE"));
    assert_eq!(
        resp["featureFlags"],
        serde_json::json!( {
          "trustEcosystemsEnabled": true
        })
    );
    assert!(resp["trustCollections"].is_array());
    let trust_collections_vec = resp["trustCollections"].as_array().unwrap();
    assert!(trust_collections_vec.contains(&serde_json::json!(
        {
            "id": collection_1.id,
            "name": "collection1",
            "logo": "logo1",
            "displayName": [{
                "lang": "en",
                "value": "name1"
            }],
            "description": [{
                "lang": "en",
                "value": "description1"
            }]
        }
    )));
    assert!(trust_collections_vec.contains(&serde_json::json!(
        {
            "id": collection_2.id,
            "name": "collection2",
            "logo": "logo2",
            "displayName": [{
                "lang": "en",
                "value": "name2"
            }],
            "description": [{
                "lang": "en",
                "value": "description2"
            }]
        }
    )));
}
