use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_identifiers_are_present_in_config() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["identifier"]["DID"],
        json!({
            "display": "identifier.did",
            "enabled": true,
            "order": 0
        })
    );
    assert_eq!(
        resp["identifier"]["CERTIFICATE"],
        json!({
            "display": "identifier.certificate",
            "enabled": true,
            "order": 1
        })
    );
}
