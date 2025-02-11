use crate::utils::context::TestContext;

#[tokio::test]
async fn test_build_info() {
    let context = TestContext::new(None).await;

    let resp = context.api.other.build_info().await;
    assert_eq!(200, resp.status());
}

#[tokio::test]
async fn test_build_info_disabled() {
    let config = indoc::indoc! {"
      app:
        enableServerInfo: false
    "}
    .to_string();
    let context = TestContext::new(Some(config.to_string())).await;

    let resp = context.api.other.build_info().await;
    assert_eq!(404, resp.status());
}

#[tokio::test]
async fn test_health() {
    let context = TestContext::new(None).await;

    let resp = context.api.other.health().await;
    assert_eq!(204, resp.status());
}

#[tokio::test]
async fn test_health_disabled() {
    let config = indoc::indoc! {"
      app:
        enableServerInfo: false
    "}
    .to_string();
    let context = TestContext::new(Some(config.to_string())).await;

    let resp = context.api.other.health().await;
    assert_eq!(404, resp.status());
}
