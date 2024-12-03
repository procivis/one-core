use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_anchor() {
    // GIVEN
    let context = TestContext::new().await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // WHEN
    let resp = context.api.trust_anchors.get(anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    body["id"].assert_eq(&anchor.id);
    assert_eq!(body["name"], anchor.name);
    assert_eq!(body["type"], anchor.r#type);
    assert_eq!(body["publisherReference"], anchor.publisher_reference);
    assert_eq!(body["isPublisher"], true);
}

#[tokio::test]
async fn test_fail_to_get_trust_anchor_unknown_id() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.trust_anchors.get(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0115", resp.error_code().await);
}
