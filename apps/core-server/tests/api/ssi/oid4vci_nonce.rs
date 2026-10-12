use similar_asserts::assert_eq;
use standardized_types::oauth2::dpop::DPOP_NONCE_HEADER;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_openid4vci_nonce() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.generate_nonce("OPENID4VCI_FINAL1").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;

    assert!(body["c_nonce"].is_string());
}

#[tokio::test]
async fn test_openid4vci_nonce_with_dpop_nonce() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .generate_nonce("OPENID4VCI_FINAL1_HAIP")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get(DPOP_NONCE_HEADER).is_some());
    let body = resp.json_value().await;

    assert!(body["c_nonce"].is_string());
}
