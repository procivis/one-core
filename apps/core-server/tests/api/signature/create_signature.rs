use assert2::let_assert;
use indoc::indoc;
use one_core::provider::signer::registration_certificate::model::WRPRegistrationCertificate;
use rcgen::{CertificateParams, KeyUsagePurpose};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::pem::Pem;
use x509_parser::time::ASN1Time;

use crate::fixtures::signature::{
    dummy_registration_certificate_payload, test_access_certificate_payload, test_csr,
    test_csr_payload,
};
use crate::fixtures::sts::{StsSetup, setup_sts};
use crate::utils::api_clients::signatures::TestCreateSignatureRequest;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_sign_wrprc_success() {
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(None).await;
    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "REGISTRATION_CERTIFICATE".to_string(),
                data: dummy_registration_certificate_payload(),
                validity_start: None,
                validity_end: None,
            },
            None,
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
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "DOES_NOT_EXIST".to_string(),
                data: Default::default(),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
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
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "REGISTRATION_CERTIFICATE".to_string(),
                data: dummy_registration_certificate_payload(),
                validity_start: Some(nbf),
                validity_end: Some(exp),
            },
            None,
        )
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
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "REGISTRATION_CERTIFICATE".to_string(),
                data: dummy_registration_certificate_payload(),
                validity_start: None,
                validity_end: Some(OffsetDateTime::now_utc() + time::Duration::days(365 * 100)),
            },
            None,
        )
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
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "REGISTRATION_CERTIFICATE".to_string(),
                data: dummy_registration_certificate_payload(),
                validity_start: Some(OffsetDateTime::now_utc() + time::Duration::days(2)),
                validity_end: Some(OffsetDateTime::now_utc() + time::Duration::days(1)),
            },
            None,
        )
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
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "REGISTRATION_CERTIFICATE".to_string(),
                data: dummy_registration_certificate_payload(),
                validity_start: Some(OffsetDateTime::now_utc() - time::Duration::days(2)),
                validity_end: Some(OffsetDateTime::now_utc() - time::Duration::days(1)),
            },
            None,
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_signature_x509_success() {
    let (context, _org, identifier, ..) = TestContext::new_with_ca_identifier(None).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "X509_CERTIFICATE".to_string(),
                data: test_csr_payload(None),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let pem = resp["result"].as_str().unwrap();

    let items = Pem::iter_from_buffer(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(items.len(), 2); // leaf + CA cert
    let certs = items
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let leaf_cert = certs.first().unwrap();
    let crl_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap()
        .unwrap()
        .parsed_extension();
    let_assert!(ParsedExtension::CRLDistributionPoints(_) = crl_ext);
    assert_eq!(leaf_cert.subject.to_string(), "CN=test cert");
    assert!(leaf_cert.validity.not_before < ASN1Time::now());
    // expires in ~ 5 years
    assert_eq!(
        leaf_cert
            .validity
            .time_to_expiration()
            .unwrap()
            .whole_days(),
        365 * 5 - 1 // -1 to account for the fractional day since issuance
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_signature_x509_intermediary_ca_success() {
    let (context, _org, identifier, ..) = TestContext::new_with_ca_identifier(None).await;

    let mut params = CertificateParams::default();
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let now_rounded = OffsetDateTime::now_utc().replace_millisecond(0).unwrap();
    let start = now_rounded + time::Duration::days(1);
    let end = now_rounded + time::Duration::days(2);

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "X509_CERTIFICATE".to_string(),
                data: test_csr_payload(Some(params)),
                validity_start: Some(start),
                validity_end: Some(end),
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let pem = resp["result"].as_str().unwrap();
    let items = Pem::iter_from_buffer(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(items.len(), 2); // leaf + CA cert
    let certs = items
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let leaf_cert = certs.first().unwrap();
    let crl_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap()
        .unwrap()
        .parsed_extension();
    let_assert!(ParsedExtension::CRLDistributionPoints(_) = crl_ext);
    assert_eq!(leaf_cert.subject.to_string(), "CN=test cert");
    assert!(leaf_cert.is_ca());
    assert!(
        leaf_cert
            .basic_constraints()
            .unwrap()
            .unwrap()
            .value
            .path_len_constraint
            .is_none()
    );
    assert_eq!(leaf_cert.validity.not_before.to_datetime(), start);
    assert_eq!(leaf_cert.validity.not_after.to_datetime(), end);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_signature_x509_intermediary_ca_disabled() {
    let signer_config = indoc! {"
        signer:
          X509_CERTIFICATE:
            params:
              private:
                payload:
                  allowCaSigning: false
        "}
    .to_string();
    let (context, _org, identifier, ..) =
        TestContext::new_with_ca_identifier(Some(signer_config)).await;

    let mut params = CertificateParams::default();
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let now_rounded = OffsetDateTime::now_utc().replace_millisecond(0).unwrap();
    let start = now_rounded + time::Duration::days(1);
    let end = now_rounded + time::Duration::days(2);

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "X509_CERTIFICATE".to_string(),
                data: test_csr_payload(Some(params)),
                validity_start: Some(start),
                validity_end: Some(end),
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0332")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_signature_x509_success_no_crl() {
    let signer_config = indoc! {"
        signer:
          X509_CERTIFICATE_2:
            display: test
            order: 1
            type: X509_CERTIFICATE
            params:
              private:
                payload:
                  maxValidityDuration: 157680000 # 5 years
                # no revocationMethod
        "}
    .to_string();
    let (context, _org, identifier, ..) =
        TestContext::new_with_ca_identifier(Some(signer_config)).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "X509_CERTIFICATE_2".to_string(),
                data: test_csr_payload(None),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let pem = resp["result"].as_str().unwrap();

    let items = Pem::iter_from_buffer(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(items.len(), 2); // leaf + CA cert
    let certs = items
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let leaf_cert = certs.first().unwrap();
    let crl_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap();
    assert!(crl_ext.is_none());
}

#[tokio::test]
async fn test_fail_on_missing_signer_specific_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["X509_CERTIFICATE_CREATE"]).await;
    let (context, _org, _did, identifier, key) = TestContext::new_with_did(Some(config)).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "REGISTRATION_CERTIFICATE".to_string(),
                data: dummy_registration_certificate_payload(),
                validity_start: None,
                validity_end: None,
            },
            Some(token),
        )
        .await;

    assert_eq!(resp.status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_signature_access_certificate_natural_person_success() {
    let (context, _org, identifier, ..) = TestContext::new_with_ca_identifier(None).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "ACCESS_CERTIFICATE".to_string(),
                data: test_access_certificate_payload(None),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let pem = resp["result"].as_str().unwrap();

    let items = Pem::iter_from_buffer(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(items.len(), 2); // leaf + CA cert
    let certs = items
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let leaf_cert = certs.first().unwrap();
    let crl_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap()
        .unwrap()
        .parsed_extension();
    let_assert!(ParsedExtension::CRLDistributionPoints(_) = crl_ext);
    assert_eq!(
        leaf_cert.subject.to_string(),
        "C=CH, OID(2.5.4.97)=orgId, CN=common name, givenName=Max, surname=Muster"
    );
    assert!(leaf_cert.validity.not_before < ASN1Time::now());
    // expires in ~ 5 years
    assert_eq!(
        leaf_cert
            .validity
            .time_to_expiration()
            .unwrap()
            .whole_days(),
        365 * 5 - 1 // -1 to account for the fractional day since issuance
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_signature_access_certificate_legal_person_success() {
    let (context, _org, identifier, ..) = TestContext::new_with_ca_identifier(None).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "ACCESS_CERTIFICATE".to_string(),
                data: test_access_certificate_payload(Some("LEGAL_PERSON".to_string())),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let pem = resp["result"].as_str().unwrap();

    let items = Pem::iter_from_buffer(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(items.len(), 2); // leaf + CA cert
    let certs = items
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let leaf_cert = certs.first().unwrap();
    let crl_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap()
        .unwrap()
        .parsed_extension();
    let_assert!(ParsedExtension::CRLDistributionPoints(_) = crl_ext);
    assert_eq!(
        leaf_cert.subject.to_string(),
        "C=CH, OID(2.5.4.97)=orgId, CN=common name, O=Org name"
    );
    assert!(leaf_cert.validity.not_before < ASN1Time::now());
    // expires in ~ 5 years
    assert_eq!(
        leaf_cert
            .validity
            .time_to_expiration()
            .unwrap()
            .whole_days(),
        365 * 5 - 1 // -1 to account for the fractional day since issuance
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_signature_access_certificate_invalid_policy_attribute_combination() {
    let (context, _org, identifier, ..) = TestContext::new_with_ca_identifier(None).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "ACCESS_CERTIFICATE".to_string(),
                data: serde_json::json!({
                    "csr": test_csr(None),
                    "organizationIdentifier": "orgId",
                    "countryName": "CH",
                    "rfc822Name": "tester@test.com",
                    "otherNamePhoneNr": "+4123456789",
                    "sanUri": "https://some-uri.com",
                    "commonName": "common name",
                    "policy": "NATURAL_PERSON",
                    "organizationName": "test"
                }),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0332")
}
