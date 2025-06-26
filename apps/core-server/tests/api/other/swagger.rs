use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_openapi_yaml() {
    let context = TestContext::new(None).await;

    let resp = context.api.other.openapi_yaml().await;
    assert_eq!(200, resp.status());
}

#[tokio::test]
async fn test_openapi_yaml_disabled() {
    let config = indoc::indoc! {"
      app:
        enableOpenApi: false
    "}
    .to_string();
    let context = TestContext::new(Some(config.to_string())).await;

    let resp = context.api.other.openapi_yaml().await;
    assert_eq!(404, resp.status());
}

#[tokio::test]
async fn test_openapi_json() {
    let context = TestContext::new(None).await;

    let resp = context.api.other.openapi_json().await;
    assert_eq!(200, resp.status());
}

#[tokio::test]
async fn test_openapi_json_disabled() {
    let config = indoc::indoc! {"
      app:
        enableOpenApi: false
    "}
    .to_string();
    let context = TestContext::new(Some(config.to_string())).await;

    let resp = context.api.other.openapi_json().await;
    assert_eq!(404, resp.status());
}
