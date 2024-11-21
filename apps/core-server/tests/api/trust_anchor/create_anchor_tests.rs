use core_server::endpoint::trust_anchor::dto::TrustAnchorRoleRest;
use one_core::model::trust_anchor::TrustAnchorRole;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_create_anchor() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .create("name", "SIMPLE_TRUST_LIST", TrustAnchorRoleRest::Publisher)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_anchor_unknown_format() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .create(
            "name",
            "NOT_SO_SIMPLE_TRUST_LIST",
            TrustAnchorRoleRest::Publisher,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0114", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_anchor_name_already_taken() {
    // GIVEN
    let context = TestContext::new().await;
    context
        .db
        .trust_anchors
        .create("name", "SIMPLE_TRUST_LIST", TrustAnchorRole::Publisher)
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .create("name", "SIMPLE_TRUST_LIST", TrustAnchorRoleRest::Publisher)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0113", resp.error_code().await);
}
