use crate::utils::context::TestContext;

#[tokio::test]
async fn test_resolve_json_ld_context() {
    let context = TestContext::new(None).await;

    let resp = context
        .api
        .jsonld
        .resolve("https://www.w3.org/2018/credentials/v1")
        .await;
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert!(body["context"].is_object());
}
