use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_capabilities_are_present_in_config() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["trustManagement"]["SIMPLE_TRUST_LIST"]["capabilities"],
        json!({
          "operations": ["LOOKUP", "PUBLISH"],
          "supportedTypes": ["DID", "CA"]
        })
    );
}
