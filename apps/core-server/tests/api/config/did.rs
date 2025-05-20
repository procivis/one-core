use serde_json::json;

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
        resp["did"]["KEY"]["capabilities"],
        json!({
            "keyAlgorithms": ["ECDSA", "EDDSA", "BBS_PLUS"],
            "operations": ["RESOLVE", "CREATE"],
            "methodNames": ["key"],
            "features": [],
            "supportedUpdateKeyTypes": [],
        })
    );
    assert_eq!(
        resp["did"]["WEB"]["capabilities"],
        json!({
            "keyAlgorithms": ["ECDSA", "EDDSA", "BBS_PLUS", "DILITHIUM"],
            "operations": ["RESOLVE", "CREATE", "DEACTIVATE"],
            "methodNames": ["web"],
            "features": [],
            "supportedUpdateKeyTypes": [],
        })
    );
    assert_eq!(
        resp["did"]["JWK"]["capabilities"],
        json!({
            "keyAlgorithms": ["ECDSA", "EDDSA", "BBS_PLUS", "DILITHIUM"],
            "operations": ["RESOLVE", "CREATE"],
            "methodNames": ["jwk"],
            "features": [],
            "supportedUpdateKeyTypes": [],
        })
    );
    assert_eq!(
        resp["did"]["X509"]["capabilities"],
        json!({
            "keyAlgorithms": ["ECDSA", "EDDSA"],
            "operations": ["RESOLVE", "CREATE"],
            "methodNames": ["x509"],
            "features": [],
            "supportedUpdateKeyTypes": [],
        })
    );
    assert_eq!(
        resp["did"]["ION"]["capabilities"],
        json!({
            "keyAlgorithms": [],
            "operations": ["RESOLVE"],
            "methodNames": ["ion"],
            "features": [],
            "supportedUpdateKeyTypes": [],
        })
    );
}

#[tokio::test]
async fn test_multikey_is_present_in_config() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["did"]["KEY"]["params"]["keys"],
        json!({
            "min": 1,
            "max": 1,
            "assertionMethod": {
                "min": 1,
                "max": 1,
            },
            "authentication": {
                "min": 1,
                "max": 1,
            },
            "capabilityDelegation": {
                "min": 1,
                "max": 1,
            },
            "capabilityInvocation": {
                "min": 1,
                "max": 1,
            },
            "keyAgreement": {
                "min": 1,
                "max": 1,
            },
        })
    );
    assert_eq!(
        resp["did"]["WEB"]["params"]["keys"],
        json!({
            "min": 1,
            "max": 5,
            "assertionMethod": {
                "min": 1,
                "max": 5,
            },
            "authentication": {
                "min": 1,
                "max": 5,
            },
            "capabilityDelegation": {
                "min": 1,
                "max": 1,
            },
            "capabilityInvocation": {
                "min": 1,
                "max": 1,
            },
            "keyAgreement": {
                "min": 1,
                "max": 1,
            },
        })
    );
    assert_eq!(
        resp["did"]["JWK"]["params"]["keys"],
        json!({
            "min": 1,
            "max": 1,
            "assertionMethod": {
                "min": 1,
                "max": 1,
            },
            "authentication": {
                "min": 1,
                "max": 1,
            },
            "capabilityDelegation": {
                "min": 1,
                "max": 1,
            },
            "capabilityInvocation": {
                "min": 1,
                "max": 1,
            },
            "keyAgreement": {
                "min": 1,
                "max": 1,
            },
        })
    );
    assert!(resp["did"]["X509"]["params"]["keys"].is_null());
    assert!(resp["did"]["ION"]["params"]["keys"].is_null());
}

#[tokio::test]
async fn test_webvh_did_method_config() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert!(resp["did"]["WEBVH"].is_object());
    assert_eq!(
        resp["did"]["WEBVH"]["capabilities"]["keyAlgorithms"]
            .as_array()
            .unwrap(),
        &["ECDSA"]
    );
    assert_eq!(
        resp["did"]["WEBVH"]["capabilities"]["methodNames"]
            .as_array()
            .unwrap(),
        &["tdw"]
    );
    assert_eq!(
        resp["did"]["WEBVH"]["capabilities"]["operations"]
            .as_array()
            .unwrap(),
        &["CREATE", "RESOLVE", "DEACTIVATE"]
    );
    assert_eq!(
        resp["did"]["WEBVH"]["capabilities"]["supportedUpdateKeyTypes"]
            .as_array()
            .unwrap(),
        &["EDDSA"]
    );
    assert_eq!(
        resp["did"]["WEBVH"]["capabilities"]["features"]
            .as_array()
            .unwrap(),
        &["SUPPORTS_EXTERNAL_HOSTING"]
    );
    assert_eq!(
        resp["did"]["WEBVH"]["params"]["keys"],
        json!({
            "min": 1,
            "max": 5,
            "assertionMethod": {
                "min": 1,
                "max": 5,
            },
            "authentication": {
                "min": 1,
                "max": 5,
            },
            "capabilityDelegation": {
                "min": 0,
                "max": 1,
            },
            "capabilityInvocation": {
                "min": 0,
                "max": 1,
            },
            "keyAgreement": {
                "min": 0,
                "max": 1,
            },
        })
    );
}
