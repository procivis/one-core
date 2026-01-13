use one_core::provider::signer::registration_certificate::model::WRPRegistrationCertificate;
use similar_asserts::assert_eq;
use time::OffsetDateTime;

use crate::fixtures::signature::dummy_registration_certificate_payload;
use crate::utils::api_clients::signatures::TestCreateSignatureRequest;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_sign_wrprc_success() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;
    let resp = context
        .api
        .signatures
        .create(TestCreateSignatureRequest {
            issuer: identifier.id,
            issuer_key: Some(key.id),
            issuer_certificate: None,
            signer: "REGISTRATION_CERTIFICATE".to_string(),
            data: dummy_registration_certificate_payload(),
            validity_start: None,
            validity_end: None,
        })
        .await;
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_on_unknown_signer() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;

    let resp = context
        .api
        .signatures
        .create(TestCreateSignatureRequest {
            issuer: identifier.id,
            issuer_key: Some(key.id),
            issuer_certificate: None,
            signer: "DOES_NOT_EXIST".to_string(),
            data: Default::default(),
            validity_start: None,
            validity_end: None,
        })
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0326");
}

#[tokio::test]
async fn test_sign_wrprc_custom_validty_success() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;
    // the JWT timestamps will not contain fractional seconds
    let now = OffsetDateTime::now_utc().replace_millisecond(0).unwrap();
    let nbf = now + time::Duration::days(1);
    let exp = now + time::Duration::days(2);
    let resp = context
        .api
        .signatures
        .create(TestCreateSignatureRequest {
            issuer: identifier.id,
            issuer_key: Some(key.id),
            issuer_certificate: None,
            signer: "REGISTRATION_CERTIFICATE".to_string(),
            data: dummy_registration_certificate_payload(),
            validity_start: Some(nbf),
            validity_end: Some(exp),
        })
        .await;
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let decomposed_token =
        WRPRegistrationCertificate::decompose_token(resp["result"].as_str().unwrap()).unwrap();
    assert_eq!(decomposed_token.payload.invalid_before.unwrap(), nbf);
    assert_eq!(decomposed_token.payload.expires_at.unwrap(), exp);
}

#[tokio::test]
async fn test_sign_wrprc_validity_too_long() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;
    let resp = context
        .api
        .signatures
        .create(TestCreateSignatureRequest {
            issuer: identifier.id,
            issuer_key: Some(key.id),
            issuer_certificate: None,
            signer: "REGISTRATION_CERTIFICATE".to_string(),
            data: dummy_registration_certificate_payload(),
            validity_start: None,
            validity_end: Some(OffsetDateTime::now_utc() + time::Duration::days(365 * 100)),
        })
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324")
}

#[tokio::test]
async fn test_sign_wrprc_validity_start_after_end() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;
    let resp = context
        .api
        .signatures
        .create(TestCreateSignatureRequest {
            issuer: identifier.id,
            issuer_key: Some(key.id),
            issuer_certificate: None,
            signer: "REGISTRATION_CERTIFICATE".to_string(),
            data: dummy_registration_certificate_payload(),
            validity_start: Some(OffsetDateTime::now_utc() + time::Duration::days(2)),
            validity_end: Some(OffsetDateTime::now_utc() + time::Duration::days(1)),
        })
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324")
}

#[tokio::test]
async fn test_sign_wrprc_validity_start_end_in_past() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;
    let resp = context
        .api
        .signatures
        .create(TestCreateSignatureRequest {
            issuer: identifier.id,
            issuer_key: Some(key.id),
            issuer_certificate: None,
            signer: "REGISTRATION_CERTIFICATE".to_string(),
            data: dummy_registration_certificate_payload(),
            validity_start: Some(OffsetDateTime::now_utc() - time::Duration::days(2)),
            validity_end: Some(OffsetDateTime::now_utc() - time::Duration::days(1)),
        })
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324")
}
