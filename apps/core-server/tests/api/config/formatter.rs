use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_format_capabilities_for_verification_key_algorithms() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    for (format, capability, expected) in [
        (
            "JWT",
            "verificationKeyAlgorithms",
            json!(["EDDSA", "ECDSA", "DILITHIUM"]),
        ),
        (
            "SD_JWT",
            "verificationKeyAlgorithms",
            json!(["EDDSA", "ECDSA", "DILITHIUM"]),
        ),
        (
            "SD_JWT_VC",
            "verificationKeyAlgorithms",
            json!(["EDDSA", "ECDSA", "DILITHIUM"]),
        ),
        (
            "JSON_LD_CLASSIC",
            "verificationKeyAlgorithms",
            json!(["EDDSA", "ECDSA"]),
        ),
        (
            "JSON_LD_BBSPLUS",
            "verificationKeyAlgorithms",
            json!(["EDDSA", "ECDSA", "DILITHIUM"]),
        ),
        (
            "MDOC",
            "verificationKeyAlgorithms",
            json!(["EDDSA", "ECDSA"]),
        ),
    ] {
        check(&resp, format, capability, expected);
    }
}

#[tokio::test]
async fn test_expected_format_features() {
    // GIVEN
    let context = TestContext::new(None).await;

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
    assert_eq!(
        resp["format"]["SD_JWT"]["capabilities"]["features"],
        json!(["SELECTIVE_DISCLOSURE", "SUPPORTS_CREDENTIAL_DESIGN"])
    );
    assert_eq!(
        resp["format"]["SD_JWT_VC"]["capabilities"]["features"],
        json!([
            "SELECTIVE_DISCLOSURE",
            "REQUIRES_SCHEMA_ID",
            "SUPPORTS_CREDENTIAL_DESIGN"
        ])
    );
    assert_eq!(
        resp["format"]["JSON_LD_CLASSIC"]["capabilities"]["features"],
        json!(["SUPPORTS_CREDENTIAL_DESIGN"])
    );
    assert_eq!(
        resp["format"]["JSON_LD_BBSPLUS"]["capabilities"]["features"],
        json!(["SUPPORTS_CREDENTIAL_DESIGN", "SELECTIVE_DISCLOSURE"])
    );
    assert_eq!(
        resp["format"]["PHYSICAL_CARD"]["capabilities"]["features"],
        json!(["REQUIRES_SCHEMA_ID"])
    );
    assert_eq!(
        resp["format"]["JWT"]["capabilities"]["features"],
        json!(["SUPPORTS_CREDENTIAL_DESIGN"])
    );
}

#[tokio::test]
async fn test_expected_format_selective_disclosure() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["format"]["MDOC"]["capabilities"]["selectiveDisclosure"],
        json!(["SECOND_LEVEL"])
    );
    assert_eq!(
        resp["format"]["SD_JWT"]["capabilities"]["selectiveDisclosure"],
        json!(["ANY_LEVEL"])
    );
    assert_eq!(
        resp["format"]["SD_JWT_VC"]["capabilities"]["selectiveDisclosure"],
        json!(["ANY_LEVEL"])
    );
    assert_eq!(
        resp["format"]["JSON_LD_CLASSIC"]["capabilities"]["selectiveDisclosure"],
        json!([])
    );
    assert_eq!(
        resp["format"]["JSON_LD_BBSPLUS"]["capabilities"]["selectiveDisclosure"],
        json!(["ANY_LEVEL"])
    );
    assert_eq!(
        resp["format"]["PHYSICAL_CARD"]["capabilities"]["selectiveDisclosure"],
        json!([])
    );
    assert_eq!(
        resp["format"]["JWT"]["capabilities"]["selectiveDisclosure"],
        json!([])
    );
}

#[tokio::test]
async fn test_format_params_have_embed_layout_properties() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    for format in resp["format"].as_object().unwrap().values() {
        assert!(!format["params"]["embedLayoutProperties"].is_null());
    }
}

#[tokio::test]
async fn test_config_formatter_issuance_did_methods_capability() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    for format in ["JWT", "SD_JWT", "JSON_LD_CLASSIC", "JSON_LD_BBSPLUS"] {
        check(
            &resp,
            format,
            "issuanceDidMethods",
            json!(["KEY", "WEB", "JWK", "X509", "WEBVH"]),
        );
    }

    check(&resp, "MDOC", "issuanceDidMethods", json!(["MDL"]));
    check(
        &resp,
        "SD_JWT_VC",
        "issuanceDidMethods",
        json!(["WEBVH", "KEY", "WEB", "JWK", "X509"]),
    );
    check(
        &resp,
        "SD_JWT_VC_SWIYU",
        "issuanceDidMethods",
        json!(["WEBVH"]),
    );
}

#[track_caller]
fn check(resp: &serde_json::Value, format: &str, capability: &str, expected: serde_json::Value) {
    assert_eq!(
        resp["format"][format]["capabilities"][capability], expected,
        "Failed for format:{format} and capability:{capability}"
    );
}
