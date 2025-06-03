use axum::http::StatusCode;
use serde_json::json;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_import_key_ecdsa() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .keys
        .import(
            organisation.id,
            "ECDSA",
            "ESTEST",
            json!({
                  "kty": "EC",
                  "alg": "ES256",
                  "kid": "13ae667d-392b-4c00-8896-079909fe85d7",
                  "crv": "P-256",
                  "x": "44WXhrEyGNuW-WAthL9_avYl-LruVMJ3uqGpfHmx7gU",
                  "y": "1Ht0VDhzbt_SmGzD_QA8ChwQUFz6SD4iwnXPl-OT00o",
                  "d": "V2rwXG2lV1HdoAf-QuAXGY3XFcVGRlt-XLWLVsY0bbg"
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = resp.json_value().await;
    let key = context.db.keys.get(&resp["id"].parse()).await;

    assert_eq!(key.name, "ESTEST");
    assert_eq!(key.key_type, "ECDSA");
    assert!(!key.public_key.is_empty());
    assert_eq!(key.organisation.unwrap().id, organisation.id);
}

#[tokio::test]
async fn test_import_key_eddsa() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .keys
        .import(
            organisation.id,
            "EDDSA",
            "EDDSATEST",
            json!({
                  "kty": "OKP",
                  "alg": "EdDSA",
                  "kid": "6ac3bed9-ad5d-4363-a62d-102d39e334f2",
                  "crv": "Ed25519",
                  "x": "pdF821j4AP1Z78wXUiVxQmNTj1mzF_wflQ0m37T0w4U",
                  "d": "mGUkA3m5YjZX187OmFM0bX5JSAVwK_ncSc1sEVOSE_Y"
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = resp.json_value().await;
    let key = context.db.keys.get(&resp["id"].parse()).await;

    assert_eq!(key.name, "EDDSATEST");
    assert_eq!(key.key_type, "EDDSA");
    assert!(!key.public_key.is_empty());
    assert_eq!(key.organisation.unwrap().id, organisation.id);
}

#[tokio::test]
async fn test_import_invalid_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .keys
        .import(
            organisation.id,
            "BBS",
            "TEST",
            json!({
                  "kty": "OKP",
                  "alg": "EdDSA",
                  "kid": "6ac3bed9-ad5d-4363-a62d-102d39e334f2",
                  "crv": "Ed25519",
                  "x": "pdF821j4AP1Z78wXUiVxQmNTj1mzF_wflQ0m37T0w4U",
                  "d": "mGUkA3m5YjZX187OmFM0bX5JSAVwK_ncSc1sEVOSE_Y"
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
