use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;

#[tokio::test]
async fn test_delete_trust_anchor() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
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
