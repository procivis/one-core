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
        resp["did"]["KEY"]["capabilities"],
        json!({
            "keyAlgorithms": ["ES256", "EDDSA", "BBS_PLUS"],
            "operations": ["RESOLVE", "CREATE"],
        })
    );
    assert_eq!(
        resp["did"]["WEB"]["capabilities"],
        json!({
            "keyAlgorithms": ["ES256", "EDDSA", "BBS_PLUS", "DILITHIUM"],
            "operations": ["RESOLVE", "CREATE", "DEACTIVATE"],
        })
    );
    assert_eq!(
        resp["did"]["JWK"]["capabilities"],
        json!({
            "keyAlgorithms": ["ES256", "EDDSA", "BBS_PLUS", "DILITHIUM"],
            "operations": ["RESOLVE", "CREATE"],
        })
    );
    assert_eq!(
        resp["did"]["X509"]["capabilities"],
        json!({
            "keyAlgorithms": ["ES256", "EDDSA"],
            "operations": ["RESOLVE", "CREATE"],
        })
    );
    assert_eq!(
        resp["did"]["ION"]["capabilities"],
        json!({
            "keyAlgorithms": [],
            "operations": ["RESOLVE"],
        })
    );
}
