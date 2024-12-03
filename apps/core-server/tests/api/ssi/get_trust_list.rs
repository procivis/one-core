use std::collections::HashSet;

use one_core::model::trust_anchor::TrustAnchor;
use one_core::model::trust_entity::{TrustEntity, TrustEntityRole, TrustEntityState};
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

pub async fn new_with_trust_list() -> (TestContext, TrustAnchor, TrustEntity, TrustEntity) {
    let (context, _, did, _) = TestContext::new_with_did().await;

    let trust_anchor = context
        .db
        .trust_anchors
        .create("ta1", "SIMPLE_TRUST_LIST", true, "reference".to_string())
        .await;

    let entity_one = context
        .db
        .trust_entities
        .create(
            "entity1",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            trust_anchor.clone(),
            did.clone(),
        )
        .await;

    let entity_two = context
        .db
        .trust_entities
        .create(
            "entity2",
            TrustEntityRole::Verifier,
            TrustEntityState::Active,
            trust_anchor.clone(),
            did,
        )
        .await;

    (context, trust_anchor, entity_one, entity_two)
}

#[tokio::test]
async fn test_get_trust_list_success() {
    // GIVEN
    let (context, trust_anchor, entity_one, entity_two) = new_with_trust_list().await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(trust_anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&trust_anchor.id);
    resp["name"].assert_eq(&trust_anchor.name);
    assert_eq!(
        [&resp["entities"][0]["name"], &resp["entities"][1]["name"]]
            .into_iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<HashSet<_>>(),
        HashSet::from_iter([entity_one.name, entity_two.name])
    );
    assert_eq!(
        [&resp["entities"][0]["did"], &resp["entities"][1]["did"]]
            .into_iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<HashSet<_>>(),
        HashSet::from_iter([
            entity_one.did.unwrap().did.to_string(),
            entity_two.did.unwrap().did.to_string()
        ])
    );
}

#[tokio::test]
async fn test_get_trust_list_failed_missing_trust_anchor() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_trust_list_failed_list_is_not_simple_trust_list() {
    // GIVEN
    let context = TestContext::new().await;

    let trust_anchor = context
        .db
        .trust_anchors
        .create(
            "ta1",
            "COMPLICATED_TRUST_LIST",
            true,
            "reference".to_string(),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(trust_anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}
