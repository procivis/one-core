use one_core::model::trust_anchor::TrustAnchorRole;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_anchor() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let anchor = context
        .db
        .trust_anchors
        .create(
            "name",
            organisation.id,
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    // WHEN
    let resp = context.api.trust_anchors.get(anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    body["id"].assert_eq(&anchor.id);
    assert_eq!(body["name"], anchor.name);
    assert_eq!(body["type"], anchor.type_field);
    assert_eq!(body["publisherReference"], anchor.publisher_reference);
    assert_eq!(body["role"], "PUBLISHER");
    assert_eq!(body["priority"], anchor.priority);
    body["organisationId"].assert_eq(&anchor.organisation_id);
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
