use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRole};
use one_core::model::trust_entity::TrustEntityRole;
use sql_data_provider::test_utilities::get_dummy_date;
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
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, &anchor)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_unknown_trust_id() {
    // GIVEN
    let context = TestContext::new().await;

    let ta = TrustAnchor {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_owned(),
        publisher_reference: Some("test".to_owned()),
        type_field: "test".to_owned(),
        organisation: None,
        priority: Some(1),
        role: TrustAnchorRole::Publisher,
    };

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, &ta)
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
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Client,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, &anchor)
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
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    context
        .db
        .trust_entities
        .create("entity", "name", TrustEntityRole::Both, anchor.clone())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("entity", "name", TrustEntityRoleRest::Both, &anchor)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0120", resp.error_code().await);
}

#[tokio::test]
async fn test_delete_trust_entity() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let anchor = context
        .db
        .trust_anchors
        .create(
            "trust-anchor",
            organisation,
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    let trust_entity = context
        .db
        .trust_entities
        .create(
            "trust-entity-id",
            "trust-entity",
            TrustEntityRole::Both,
            anchor,
        )
        .await;

    // WHEN
    let resp = context.api.trust_entities.delete(trust_entity.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    assert!(context
        .db
        .trust_entities
        .get(trust_entity.id)
        .await
        .is_none());
}

#[tokio::test]
async fn test_delete_trust_entity_fails_if_entity_not_found() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .delete(Uuid::new_v4().into())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0121", resp.error_code().await);
}
