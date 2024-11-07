use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_capabilities_are_present_in_config() {
    // GIVEN
    let context = TestContext::new().await;

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
        resp["keyAlgorithm"]["ES256"]["capabilities"],
        json!({ "features": ["GENERATE_CSR"] })
    );
    assert_eq!(
        resp["keyAlgorithm"]["DILITHIUM"]["capabilities"],
        json!({ "features": [] })
    );
    assert_eq!(
        resp["keyAlgorithm"]["BBS_PLUS"]["capabilities"],
        json!({ "features": [] })
    );
}
