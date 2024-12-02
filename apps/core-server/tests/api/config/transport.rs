use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_transport_params_are_filtered_in_config() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["transport"]["HTTP"]["params"], json!({}));
}
