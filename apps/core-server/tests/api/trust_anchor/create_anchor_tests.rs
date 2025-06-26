use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;

#[tokio::test]
async fn test_create_anchor() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .create("name", "SIMPLE_TRUST_LIST", true)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_anchor_unknown_format() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .create("name", "NOT_SO_SIMPLE_TRUST_LIST", true)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0114", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_anchor_name_already_taken() {
    // GIVEN
    let context = TestContext::new(None).await;
    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name".to_string(),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .create("name", "SIMPLE_TRUST_LIST", true)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0113", resp.error_code().await);
}
