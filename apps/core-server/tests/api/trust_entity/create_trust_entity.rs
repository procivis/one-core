use core_server::endpoint::ssi::dto::PatchTrustEntityActionRestDTO;
use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use ct_codecs::{Base64, Encoder};
use one_core::model::trust_anchor::TrustAnchor;
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;

#[tokio::test]
async fn test_create_trust_entity() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("name", TrustEntityRoleRest::Both, &anchor, &did)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_unknown_trust_id() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    let ta = TrustAnchor {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_owned(),
        publisher_reference: "test".to_string(),
        r#type: "test".to_owned(),
        is_publisher: true,
    };

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("name", TrustEntityRoleRest::Both, &ta, &did)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0115", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_trust_role_is_not_publish() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            is_publisher: false,
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("name", TrustEntityRoleRest::Both, &anchor, &did)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0123", resp.error_code().await);
}

#[tokio::test]
async fn test_patch_trust_entity() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let trust_entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor,
            did,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .patch(trust_entity.id, PatchTrustEntityActionRestDTO::Remove)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    assert_eq!(
        context
            .db
            .trust_entities
            .get(trust_entity.id)
            .await
            .unwrap()
            .state,
        TrustEntityState::Removed
    );
}

#[tokio::test]
async fn test_delete_trust_entity_fails_if_entity_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .patch(Uuid::new_v4().into(), PatchTrustEntityActionRestDTO::Remove)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0121", resp.error_code().await);
}

#[tokio::test]
async fn test_create_trust_entity_fails_did_already_used() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let resp = context
        .api
        .trust_entities
        .create("name", TrustEntityRoleRest::Both, &anchor, &did)
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create("name2", TrustEntityRoleRest::Both, &anchor, &did)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_remote_trust_entity_logo_too_big() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_remote(
            "name",
            TrustEntityRoleRest::Both,
            None,
            &did,
            Some(format!(
                "data:image/png;base64,{}",
                Base64::encode_to_string([0; 60_000]).unwrap()
            )),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0193")
}
