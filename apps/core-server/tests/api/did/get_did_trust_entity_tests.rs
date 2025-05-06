use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_entity_by_did_success() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;
    let trust_anchor_id = Uuid::new_v4();
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id,
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id
            ),
            ..Default::default()
        })
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "name",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor.clone(),
            did.clone(),
        )
        .await;

    // WHEN
    let resp = context.api.dids.get_trust_entity(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["id"].assert_eq(&entity.id);
}

#[tokio::test]
async fn test_get_trust_entity_by_did_multiple_anchors_success() {
    // GIVEN
    let (context, org, did1, ..) = TestContext::new_with_did(None).await;

    let trust_anchor_id1 = Uuid::new_v4();
    let anchor1 = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id1,
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id1
            ),
            ..Default::default()
        })
        .await;
    context
        .db
        .trust_entities
        .create(
            "name1",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor1.clone(),
            did1,
        )
        .await;

    let trust_anchor_id2 = Uuid::new_v4();
    let anchor2 = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id2,
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id2
            ),
            ..Default::default()
        })
        .await;

    let did2 = context
        .db
        .dids
        .create(Some(org.clone()), Default::default())
        .await;
    let entity = context
        .db
        .trust_entities
        .create(
            "name2",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor2.clone(),
            did2.clone(),
        )
        .await;

    // WHEN
    let resp = context.api.dids.get_trust_entity(&did2.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["id"].assert_eq(&entity.id);
    body["name"].assert_eq(&entity.name);
    body["did"]["id"].assert_eq(&entity.did.unwrap().id);
}

#[tokio::test]
async fn test_get_trust_entity_by_did_fail_invalid_url() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;
    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            publisher_reference: "invalid url".to_string(),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context.api.dids.get_trust_entity(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0185")
}

#[tokio::test]
async fn test_get_trust_entity_by_did_fail_not_found() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    // WHEN
    let resp = context.api.dids.get_trust_entity(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0186")
}
