use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use one_core::model::{trust_anchor::TrustAnchorRole, trust_entity::TrustEntityRole};
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_create_trust_entity() {
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
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, anchor.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_unknown_trust_id() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, Uuid::new_v4())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0115", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_trust_role_is_not_publish() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let anchor = context
        .db
        .trust_anchors
        .create(
            "name",
            organisation.id,
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Client,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, anchor.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0123", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_entity_is_present() {
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

    context
        .db
        .trust_entities
        .create("entity", "name", TrustEntityRole::Both, anchor.id)
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, anchor.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0120", resp.error_code().await);
}
