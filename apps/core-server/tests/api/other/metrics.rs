use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_metrics() {
    let context = TestContext::new(None).await;

    let resp = context.api.other.metrics().await;
    assert_eq!(200, resp.status());
}

#[tokio::test]
async fn test_metrics_disabled() {
    let config = indoc::indoc! {"
      app:
        enableMetrics: false
    "}
    .to_string();
    let context = TestContext::new(Some(config.to_string())).await;

    let resp = context.api.other.metrics().await;
    assert_eq!(404, resp.status());
}
