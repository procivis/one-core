use one_core::model::trust_anchor::TrustAnchorRole;
use one_core::model::trust_entity::TrustEntityRole;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_trust_anchor() {
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
        .create("entity_id", "name", TrustEntityRole::Both, anchor.id)
        .await;

    // WHEN
    let resp = context.api.trust_anchors.delete(anchor.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let resp = context.api.trust_anchors.get(anchor.id).await;
    assert_eq!(resp.status(), 404);
}
