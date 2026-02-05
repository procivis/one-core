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
        resp["keyAlgorithm"]["EDDSA"]["capabilities"],
        json!({ "features": ["GENERATE_CSR"] })
    );
    assert_eq!(
        resp["keyAlgorithm"]["ECDSA"]["capabilities"],
        json!({ "features": ["GENERATE_CSR"] })
    );
    assert_eq!(
        resp["keyAlgorithm"]["ML_DSA"]["capabilities"],
        json!({ "features": [] })
    );
    assert_eq!(
        resp["keyAlgorithm"]["BBS_PLUS"]["capabilities"],
        json!({ "features": [] })
    );
}
