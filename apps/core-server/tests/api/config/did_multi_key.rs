use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_multikey_is_present_in_config() {
    // GIVEN
    let context = TestContext::new().await;

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
                "max": 2,
            },
            "authentication": {
                "min": 0,
                "max": 2,
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