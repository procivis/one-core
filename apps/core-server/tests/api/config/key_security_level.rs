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
        resp["keySecurityLevel"]["BASIC"]["capabilities"],
        json!({ "OPENID_SECURITY_LEVEL": ["iso_18045_basic"] })
    );
    assert_eq!(
        resp["keySecurityLevel"]["MODERATE"]["capabilities"],
        json!({ "OPENID_SECURITY_LEVEL": ["iso_18045_moderate"] })
    );
}
