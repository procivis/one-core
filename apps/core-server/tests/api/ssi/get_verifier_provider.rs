use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;

#[tokio::test]
async fn test_get_verifier_provider_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_verifier_provider("PROCIVIS_ONE").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["verifierName"], "Procivis One Verifier");
    assert_eq!(body["appVersion"]["minimum"], "v1.50.0");
    assert_eq!(body["appVersion"]["minimumRecommended"], "v1.55.0");

    let reject = body["appVersion"]["reject"].as_array().unwrap();
    assert_eq!(reject.len(), 1);
    assert_eq!(reject[0], "v1.51.0");

    assert_eq!(
        body["appVersion"]["updateScreen"]["link"],
        "https//example.com"
    );
    assert_eq!(body["featureFlags"]["trustEcosystemsEnabled"], true);
    assert_eq!(body["trustCollections"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_get_verifier_provider_failure() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_verifier_provider("DOES_NOT_EXIST")
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_verifier_provider_with_trust_collection() {
    // GIVEN
    let collection_id = Uuid::new_v4().into();
    let config = indoc::formatdoc! {"
      verifierProvider:
        PROCIVIS_ONE:
          params:
            public:
              trustCollections:
                - id: {collection_id}
                  logo: Logo
                  displayName:
                    en: Name
                  description:
                    en: Description
    "};
    let (context, organisation) = TestContext::new_with_organisation(Some(config)).await;

    let collection = context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                id: Some(collection_id),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_verifier_provider("PROCIVIS_ONE").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;

    assert_eq!(body["featureFlags"]["trustEcosystemsEnabled"], true);
    let trust_collections = body["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 1);
    assert_eq!(
        trust_collections[0],
        json!({
            "id": collection.id,
            "name": collection.name,
            "logo": "Logo",
            "displayName": [{
                "lang": "en",
                "value": "Name"
            }],
            "description": [{
                "lang": "en",
                "value": "Description"
            }]
        })
    );
}
