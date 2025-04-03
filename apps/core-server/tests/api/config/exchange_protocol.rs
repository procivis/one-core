use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_exchange_protocol_capabilities() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["verificationProtocol"]["OPENID4VP_DRAFT20"]["capabilities"]["supportedTransports"],
        json!(["HTTP", "BLE", "MQTT"])
    );
    assert_eq!(
        resp["verificationProtocol"]["MDOC_OPENID4VP"]["capabilities"]["supportedTransports"],
        json!(["HTTP", "BLE", "MQTT"])
    );
}
