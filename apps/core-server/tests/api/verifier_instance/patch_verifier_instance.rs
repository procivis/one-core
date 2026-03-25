use serde_json::json;
use similar_asserts::assert_eq;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;
use crate::utils::db_clients::verifier_instances::TestVerifierInstanceParams;

#[tokio::test]
async fn test_edit_verifier_instance() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let verifier_instance = context
        .db
        .verifier_instances
        .create(
            org.clone(),
            TestVerifierInstanceParams {
                provider_type: Some("PROCIVIS_ONE".to_string()),
                provider_url: Some("https://verifier.provider".to_string()),
                ..Default::default()
            },
        )
        .await;

    let mock_server = MockServer::start().await;

    let collection = context
        .db
        .trust_collections
        .create(
            org,
            TestTrustCollectionParams {
                remote_trust_collection_url: Some(
                    format!("{}/collection", mock_server.uri()).parse().unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    Mock::given(method(Method::GET))
        .and(path("/collection"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "collection",
            "trustLists": [{
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "name": "list-name",
                "reference": "reference",
                "role": "PID_PROVIDER",
                "type": "LOTE_SUBSCRIBER"
            }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .verifier_instances
        .patch_verifier_instance(&verifier_instance.id, &[collection.id])
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let subscriptions = context
        .db
        .trust_list_subscriptions
        .list(Default::default())
        .await;

    assert_eq!(subscriptions.len(), 1);
    let subscription = &subscriptions[0];
    assert_eq!(subscription.name, "list-name");
    assert_eq!(subscription.trust_collection_id, collection.id);

    // WHEN
    let resp = context
        .api
        .verifier_instances
        .patch_verifier_instance(&verifier_instance.id, &[])
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let subscriptions = context
        .db
        .trust_list_subscriptions
        .list(Default::default())
        .await;
    assert_eq!(subscriptions.len(), 0);
}
