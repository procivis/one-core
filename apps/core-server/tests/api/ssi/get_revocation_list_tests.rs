use one_core::model::revocation_list::StatusListCredentialFormat;
use similar_asserts::assert_eq;
use time::OffsetDateTime;

use crate::utils::context::TestContext;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

#[tokio::test]
async fn test_get_revocation_list_success() {
    // GIVEN
    let (context, _, _, identifier, _) = TestContext::new_with_did(None).await;

    let status_list_credential_jwt = "test-jwt";
    let revocation_list = context
        .db
        .revocation_lists
        .create(
            identifier,
            Some(TestingRevocationListParams {
                formatted_list: Some(status_list_credential_jwt.as_bytes().to_vec()),
                ..Default::default()
            }),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_revocation_list(revocation_list.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.text().await;
    assert_eq!(resp, status_list_credential_jwt);
}

#[tokio::test]
async fn test_get_crl_success() {
    let (context, _, identifier, certificate, _) =
        TestContext::new_with_certificate_identifier(None).await;

    let crl_content = b"test-CRL-content";
    let list = context
        .db
        .revocation_lists
        .create(
            identifier,
            Some(TestingRevocationListParams {
                formatted_list: Some(crl_content.to_vec()),
                format: Some(StatusListCredentialFormat::X509Crl),
                r#type: Some("CRL".into()),
                last_modified: Some(OffsetDateTime::now_utc()),
                issuer_certificate: Some(certificate),
                ..Default::default()
            }),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_crl(list.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()[reqwest::header::CONTENT_TYPE],
        "application/pkix-crl"
    );
    assert_eq!(resp.bytes().await, crl_content);
}
