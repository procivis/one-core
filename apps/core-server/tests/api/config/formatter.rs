use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_format_capabilities_for_verification_key_algorithms() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["format"]["JWT"]["capabilities"]["verificationKeyAlgorithms"],
        json!(["EDDSA", "ES256", "DILITHIUM"])
    );
    assert_eq!(
        resp["format"]["SDJWT"]["capabilities"]["verificationKeyAlgorithms"],
        json!(["EDDSA", "ES256", "DILITHIUM"])
    );
    assert_eq!(
        resp["format"]["JSON_LD_CLASSIC"]["capabilities"]["verificationKeyAlgorithms"],
        json!(["EDDSA", "ES256"])
    );
    assert_eq!(
        resp["format"]["JSON_LD_BBSPLUS"]["capabilities"]["verificationKeyAlgorithms"],
        json!(["EDDSA", "ES256", "DILITHIUM"])
    );
    assert_eq!(
        resp["format"]["MDOC"]["capabilities"]["verificationKeyAlgorithms"],
        json!(["EDDSA", "ES256"])
    );
}

#[tokio::test]
async fn test_mdoc_format_features() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["format"]["MDOC"]["capabilities"]["features"],
        json!([
            "SELECTIVE_DISCLOSURE",
            "REQUIRES_SCHEMA_ID",
            "SUPPORTS_CREDENTIAL_DESIGN"
        ])
    );
}

#[tokio::test]
async fn test_format_params_have_embed_layout_properties() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    for format in resp["format"].as_object().unwrap().values() {
        assert!(!format["params"]["embedLayoutProperties"].is_null());
    }
}
