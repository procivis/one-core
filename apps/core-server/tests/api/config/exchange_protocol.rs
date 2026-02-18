use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_verification_protocol_capabilities() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let draft20 = &resp["verificationProtocol"]["OPENID4VP_DRAFT20"]["capabilities"];
    assert_eq!(draft20["features"], json!(["SUPPORTS_WEBHOOKS"]));
    assert_eq!(draft20["supportedTransports"], json!(["HTTP"]));
    assert_eq!(draft20["didMethods"], json!(["KEY", "JWK", "WEB", "WEBVH"]));

    let draft25 = &resp["verificationProtocol"]["OPENID4VP_DRAFT25"]["capabilities"];
    assert_eq!(draft25["features"], json!(["SUPPORTS_WEBHOOKS"]));
    assert_eq!(draft25["supportedTransports"], json!(["HTTP"]));
    assert_eq!(draft25["didMethods"], json!(["KEY", "JWK", "WEB", "WEBVH"]));

    let mdoc = &resp["verificationProtocol"]["MDOC_OPENID4VP"]["capabilities"];
    assert_eq!(mdoc["features"], json!(["SUPPORTS_WEBHOOKS"]));
    assert_eq!(mdoc["supportedTransports"], json!(["HTTP"]));
    assert_eq!(mdoc["didMethods"], json!(["KEY", "JWK", "WEB", "WEBVH"]))
}
