use serde_json::json;
use similar_asserts::assert_eq;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;
use crate::utils::db_clients::verifier_instances::TestVerifierInstanceParams;

#[tokio::test]
async fn get_verifier_instance_trust_collections_empty() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "verifierName": "verifier-name",
          "featureFlags": {
            "trustEcosystemsEnabled": true
          },
          "trustCollections": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let instance = context
        .db
        .verifier_instances
        .create(
            org,
            TestVerifierInstanceParams {
                provider_url: Some(mock_server.uri()),
                provider_type: Some("PROCIVIS_ONE".to_string()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .get_trust_collections(&instance.id)
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let trust_collections = resp["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 0);
}

#[tokio::test]
async fn get_verifier_instance_trust_collections_one_collection() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "verifierName": "verifier-name",
          "featureFlags": {
            "trustEcosystemsEnabled": true
          },
          "trustCollections": [{
              "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "logo": "logo",
              "name": "collection",
              "description": [{
                  "lang": "en",
                  "value": "desc"
              }],
              "displayName": [{
                  "lang": "en",
                  "value": "name"
              }]
          }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let instance = context
        .db
        .verifier_instances
        .create(
            org.clone(),
            TestVerifierInstanceParams {
                provider_url: Some(mock_server.uri()),
                provider_type: Some("PROCIVIS_ONE".to_string()),
                ..Default::default()
            },
        )
        .await;

    let collection = context
        .db
        .trust_collections
        .create(
            org,
            TestTrustCollectionParams {
                name: Some("collection".to_string()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .get_trust_collections(&instance.id)
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let trust_collections = resp["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 1);
    assert_eq!(
        trust_collections[0],
        json!({
          "id": collection.id,
          "selected": false,
          "logo": "logo",
          "name": "collection",
          "description": [{
              "lang": "en",
              "value": "desc"
          }],
          "displayName": [{
              "lang": "en",
              "value": "name"
          }]
        })
    );
}
