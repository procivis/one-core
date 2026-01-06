use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_sign_wrprc_success() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;

    let payload = serde_json::json!({
        "name": "Jane Doe",
        "sub": {
            "given_name": "Jane",
            "family_name": "Doe",
            "id": "TIN-1234567890"
        },
        "info_uri": "https://example.com",
        "country": "DE",
        "privacy_policy": "https://example-company.com/en/privacy-policy",
        "policy_id": [],
        "certificate_policy": "https://registrar.example.com/certificate-policy",
        "purpose": [],
        "credentials": [],
        "entitlements": [
            "https://uri.etsi.org/19475/Entitlement/PID_Provider"
        ],
        "service": [],
        "status": {}
    });

    let resp = context
        .api
        .signatures
        .create(
            identifier.id,
            Some(key.id),
            "REGISTRATION_CERTIFICATE".to_owned(),
            payload,
        )
        .await;
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_on_unknown_signer() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;

    let resp = context
        .api
        .signatures
        .create(
            identifier.id,
            Some(key.id),
            "DOES_NOT_EXIST".to_owned(),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(resp.status(), 500);
}
