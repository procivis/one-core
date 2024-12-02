use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_trust_anchor() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did().await;

    let anchor = context
        .db
        .trust_anchors
        .create("name", "SIMPLE_TRUST_LIST", true, "reference".to_string())
        .await;

    context
        .db
        .trust_entities
        .create(
            "name",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor.clone(),
            did,
        )
        .await;

    // WHEN
    let resp = context.api.trust_anchors.delete(anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let resp = context.api.trust_anchors.get(anchor.id).await;
    assert_eq!(resp.status(), 404);
}
