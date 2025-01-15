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
        resp["exchange"]["OPENID4VC"]["capabilities"]["operations"],
        json!(["ISSUANCE", "VERIFICATION"])
    );
    assert_eq!(
        resp["exchange"]["MDOC_OPENID4VP"]["capabilities"]["operations"],
        json!(["VERIFICATION"])
    );
    assert_eq!(
        resp["exchange"]["OPENID4VC"]["capabilities"]["supported_transports"],
        json!(["HTTP", "BLE", "MQTT"])
    );
    assert_eq!(
        resp["exchange"]["MDOC_OPENID4VP"]["capabilities"]["supported_transports"],
        json!(["HTTP", "BLE", "MQTT"])
    );
}
