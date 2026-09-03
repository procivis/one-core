use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_certificate_success() {
    // GIVEN
    let (context, _, _, certificate, _) = TestContext::new_with_certificate_identifier(None).await;

    // WHEN
    let resp = context.api.ssi.get_certificate(certificate.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/pem-certificate-chain"
    );

    let content = resp.text().await;
    assert_eq!(content, certificate.chain);
}

#[tokio::test]
async fn test_get_certificate_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_certificate(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}
