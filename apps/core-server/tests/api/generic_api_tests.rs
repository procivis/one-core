use crate::utils::context::TestContext;

#[tokio::test]
async fn test_expected_response_headers_are_present() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    // note: this test should work regardless of the endpoint
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let header_value = resp
        .headers()
        .get("X-Content-Type-Options")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(header_value, "nosniff");

    let header_value = resp
        .headers()
        .get("Cache-Control")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(header_value, "no-store");

    let header_value = resp.headers().get("Pragma").unwrap().to_str().unwrap();
    assert_eq!(header_value, "no-cache");
}
