use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_remote_trust_entity() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let trust_entity_id = Uuid::new_v4();
    Mock::given(method(Method::POST))
        .and(path("/ssi/trust-entity/v1"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!(
            { "id": trust_entity_id }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name".to_string(),
            publisher_reference: format!("{}/ssi/trust/v1/{}", mock_server.uri(), Uuid::new_v4()),
            is_publisher: false,
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_remote(
            "name",
            TrustEntityRoleRest::Both,
            Some(anchor),
            &did,
            Some("data:image/png;base64,AAAAAAAAAAAAAA==".to_string()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let body = resp.json_value().await;
    body["id"].assert_eq(&trust_entity_id);
}

#[tokio::test]
async fn test_fail_create_remote_trust_entity_invalid_logo() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_remote(
            "name",
            TrustEntityRoleRest::Both,
            None,
            &did,
            Some("invalid logo".to_string()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0193")
}
