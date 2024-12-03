use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_anchor() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did().await;
    let anchor = context
        .db
        .trust_anchors
        .create("name", "SIMPLE_TRUST_LIST", true, "reference".to_string())
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
    let resp = context.api.trust_entities.get(entity.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;

    body["id"].assert_eq(&entity.id);
    body["name"].assert_eq(&entity.name);
    body["logo"].assert_eq(&entity.logo);
    body["website"].assert_eq(&entity.website);
    body["termsUrl"].assert_eq(&entity.terms_url);
    body["privacyUrl"].assert_eq(&entity.privacy_url);
    body["role"].assert_eq(&"ISSUER".to_owned());
    body["trustAnchor"]["id"].assert_eq(&anchor.id);
    body["did"]["id"].assert_eq(&did.id);
}

#[tokio::test]
async fn test_fail_to_get_trust_entity_unknown_id() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.trust_entities.get(Uuid::new_v4().into()).await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0121", resp.error_code().await);
}
