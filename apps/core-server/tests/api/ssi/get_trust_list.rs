use crate::utils::{context::TestContext, field_match::FieldHelpers};
use one_core::model::organisation::Organisation;
use one_core::model::trust_anchor::{TrustAnchor, TrustAnchorRole};
use one_core::model::trust_entity::{TrustEntity, TrustEntityRole};
use uuid::Uuid;

pub async fn new_with_trust_list() -> (
    TestContext,
    Organisation,
    TrustAnchor,
    TrustEntity,
    TrustEntity,
) {
    let (context, organisation) = TestContext::new_with_organisation().await;

    let trust_anchor = context
        .db
        .trust_anchors
        .create(
            "ta1",
            organisation.id,
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    let entity_one = context
        .db
        .trust_entities
        .create(
            "entity1",
            "entity1",
            TrustEntityRole::Issuer,
            trust_anchor.id,
        )
        .await;

    let entity_two = context
        .db
        .trust_entities
        .create(
            "entity2",
            "entity2",
            TrustEntityRole::Verifier,
            trust_anchor.id,
        )
        .await;

    (context, organisation, trust_anchor, entity_one, entity_two)
}

#[tokio::test]
async fn test_get_trust_list_success() {
    // GIVEN
    let (context, _organisation, trust_anchor, entity_one, entity_two) =
        new_with_trust_list().await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(trust_anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&trust_anchor.id);
    resp["name"].assert_eq(&trust_anchor.name);
    resp["entities"][0]["name"].assert_eq(&entity_one.name);
    resp["entities"][1]["name"].assert_eq(&entity_two.name);
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
    let (context, organisation) = TestContext::new_with_organisation().await;

    let trust_anchor = context
        .db
        .trust_anchors
        .create(
            "ta1",
            organisation.id,
            "COMPLICATED_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_trust_list(trust_anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}
