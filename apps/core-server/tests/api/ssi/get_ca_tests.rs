use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_ca_success() {
    // GIVEN
    let (context, _, _, certificate, _) = TestContext::new_with_ca_identifier(None).await;

    // WHEN
    let resp = context.api.ssi.get_ca(certificate.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/pkix-cert"
    );

    let content = resp.bytes().await;
    assert!(!content.is_empty());
    assert!(content.len() < certificate.chain.len());
}
