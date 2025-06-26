use std::collections::HashSet;

use one_core::model::organisation::Organisation;
use one_core::model::trust_anchor::TrustAnchor;
use one_core::model::trust_entity::{
    TrustEntity, TrustEntityRole, TrustEntityState, TrustEntityType,
};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingDidParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

pub async fn new_with_trust_list() -> (
    TestContext,
    Organisation,
    TrustAnchor,
    TrustEntity,
    TrustEntity,
) {
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let trust_anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity_one = context
        .db
        .trust_entities
        .create(
            "entity1",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            trust_anchor.clone(),
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let did2 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    let entity_two = context
        .db
        .trust_entities
        .create(
            "entity2",
            TrustEntityRole::Verifier,
            TrustEntityState::Active,
            trust_anchor.clone(),
            TrustEntityType::Did,
            did2.did.into(),
            None,
            did2.organisation,
        )
        .await;

    (context, organisation, trust_anchor, entity_one, entity_two)
}

#[tokio::test]
async fn test_get_trust_list_success() {
    // GIVEN
    let (context, _, trust_anchor, entity_one, entity_two) = new_with_trust_list().await;

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
            entity_one.entity_key.to_string(),
            entity_two.entity_key.to_string()
        ])
    );
}

#[tokio::test]
async fn test_get_trust_list_failed_missing_trust_anchor() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_trust_list_failed_list_is_not_simple_trust_list() {
    // GIVEN
    let context = TestContext::new(None).await;

    let trust_anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            r#type: "COMPLICATED_TRUST_LIST".to_string(),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(trust_anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_trust_list_filters_not_active() {
    // GIVEN
    let (context, organisation, trust_anchor, entity_one, entity_two) = new_with_trust_list().await;
    let did3 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    context
        .db
        .trust_entities
        .create(
            "entity3",
            TrustEntityRole::Verifier,
            TrustEntityState::Withdrawn,
            trust_anchor.clone(),
            TrustEntityType::Did,
            did3.did.into(),
            None,
            did3.organisation,
        )
        .await;
    let did4 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    context
        .db
        .trust_entities
        .create(
            "entity4",
            TrustEntityRole::Verifier,
            TrustEntityState::Removed,
            trust_anchor.clone(),
            TrustEntityType::Did,
            did4.did.into(),
            None,
            did4.organisation,
        )
        .await;
    let did5 = context
        .db
        .dids
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    context
        .db
        .trust_entities
        .create(
            "entity5",
            TrustEntityRole::Verifier,
            TrustEntityState::RemovedAndWithdrawn,
            trust_anchor.clone(),
            TrustEntityType::Did,
            did5.did.into(),
            None,
            did5.organisation,
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(trust_anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["entities"].as_array().unwrap().len(), 2);
    assert_eq!(
        [&resp["entities"][0]["name"], &resp["entities"][1]["name"]]
            .into_iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect::<HashSet<_>>(),
        HashSet::from_iter([entity_one.name, entity_two.name])
    );
}
