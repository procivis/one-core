use std::str::FromStr;

use assert2::let_assert;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use indoc::indoc;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::key::Key;
use one_core::provider::signer::registration_certificate::model::WRPRegistrationCertificate;
use one_core::provider::signer::swiyu_proof_of_possession::ProofOfPossession;
use rcgen::{CertificateParams, KeyUsagePurpose, SanType};
use shared_types::DidValue;
use similar_asserts::assert_eq;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::{OID_X509_EXT_CRL_DISTRIBUTION_POINTS, OID_X509_EXT_KEY_USAGE};
use x509_parser::pem::Pem;
use x509_parser::time::ASN1Time;

use crate::fixtures::signature::{
    dummy_registration_certificate_payload, test_access_certificate_payload, test_csr,
    test_csr_payload,
};
use crate::fixtures::sts::{StsSetup, setup_sts};
use crate::fixtures::{TestingDidParams, TestingIdentifierParams};
use crate::utils::api_clients::signatures::TestCreateSignatureRequest;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_sign_wrprc_success() {
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(None).await;
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
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(None).await;

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
    assert_eq!(resp.error_code().await, "BR_0430");
}

#[tokio::test]
async fn test_sign_wrprc_custom_validty_success() {
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(None).await;
    // the JWT timestamps will not contain fractional seconds
    let now = one_core::clock::now_utc().replace_millisecond(0).unwrap();
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
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(None).await;
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
                validity_end: Some(one_core::clock::now_utc() + time::Duration::days(365 * 100)),
            },
            None,
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324")
}

#[tokio::test]
async fn test_sign_wrprc_validity_start_after_end() {
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(None).await;
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
                validity_start: Some(one_core::clock::now_utc() + time::Duration::days(2)),
                validity_end: Some(one_core::clock::now_utc() + time::Duration::days(1)),
            },
            None,
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324")
}

#[tokio::test]
async fn test_sign_wrprc_validity_start_end_in_past() {
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(None).await;
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
                validity_start: Some(one_core::clock::now_utc() - time::Duration::days(2)),
                validity_end: Some(one_core::clock::now_utc() - time::Duration::days(1)),
            },
            None,
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324")
}

#[tokio::test(flavor = "multi_thread")]
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

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_x509_intermediary_ca_success() {
    let (context, _org, identifier, ..) = TestContext::new_with_ca_identifier(None).await;

    let mut params = CertificateParams::default();
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let now_rounded = one_core::clock::now_utc().replace_millisecond(0).unwrap();
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
    assert_eq!(
        leaf_cert
            .basic_constraints()
            .unwrap()
            .unwrap()
            .value
            .path_len_constraint,
        Some(0)
    );
    assert_eq!(leaf_cert.validity.not_before.to_datetime(), start);
    assert_eq!(leaf_cert.validity.not_after.to_datetime(), end);
}

#[tokio::test]
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

    let now_rounded = one_core::clock::now_utc().replace_millisecond(0).unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_x509_success_no_crl() {
    let signer_config = indoc! {"
        signer:
          X509_CERTIFICATE_2:
            display: test
            order: 1
            type: X509_CERTIFICATE
            params:
              private:
                payload: {}
                # no revocationMethod
              public:
                maxValidityDurationSeconds: 157680000 # 5 years
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

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_x509_san_dns() {
    let (context, _org, identifier, ..) = TestContext::new_with_ca_identifier(None).await;

    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName("procivis.ch".try_into().unwrap())];

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

    let san_ext = leaf_cert.subject_alternative_name().unwrap().unwrap();
    let dns_name = san_ext.value.general_names.first().unwrap();
    assert2::assert!(let GeneralName::DNSName("procivis.ch") = dns_name);
}

#[tokio::test]
async fn test_fail_on_missing_signer_specific_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["X509_CERTIFICATE_CREATE"], None).await;
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(Some(config)).await;

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

#[tokio::test(flavor = "multi_thread")]
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
    assert_eq!(
        leaf_cert.subject.to_string(),
        "C=CH, OID(2.5.4.81)=https://some-url.com, CN=common name, serialNumber=orgId, givenName=Max, surname=Muster"
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

    let crl_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap()
        .unwrap()
        .parsed_extension();
    let_assert!(ParsedExtension::CRLDistributionPoints(_) = crl_ext);

    let key_usage_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_KEY_USAGE)
        .unwrap();
    assert!(key_usage_ext.is_some());
}

#[tokio::test(flavor = "multi_thread")]
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
    assert_eq!(
        leaf_cert.subject.to_string(),
        "C=CH, OID(2.5.4.81)=https://some-url.com, CN=common name, OID(2.5.4.97)=orgId, O=Org name"
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

    let crl_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap()
        .unwrap()
        .parsed_extension();
    let_assert!(ParsedExtension::CRLDistributionPoints(_) = crl_ext);

    let key_usage_ext = leaf_cert
        .get_extension_unique(&OID_X509_EXT_KEY_USAGE)
        .unwrap();
    assert!(key_usage_ext.is_some());
}

#[tokio::test]
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
                    "organizationName": "test",
                    "nationalRegistryUrl": "https://some-url.com"
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

/// Creates a local DID identifier of the given `did_method` with a single assertion method key.
async fn setup_did_identifier(
    additional_config: Option<String>,
    did_method: &str,
    did: &str,
) -> (TestContext, Identifier, Key) {
    let (context, organisation) = TestContext::new_with_organisation(additional_config).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some(did_method.into()),
                did: Some(DidValue::from_str(did).unwrap()),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.to_owned(),
                    reference: format!("key-{}", key.id),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                ..Default::default()
            },
        )
        .await;

    (context, identifier, key)
}

const TEST_TDW_DID: &str = "did:tdw:QmdSU7F2rF7YnRRJLpQeYbxtEnwHWReNRSGCJ4Y5cGxrRK:example.com";

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_swiyu_proof_of_possession_success() {
    let (context, identifier, key) = setup_did_identifier(None, "TDW", TEST_TDW_DID).await;

    let before = one_core::clock::now_utc().replace_millisecond(0).unwrap();
    let exp = before + time::Duration::minutes(2);

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "SWIYU_PROOF_OF_POSSESSION".to_string(),
                data: serde_json::json!({ "nonce": "Your Nonce" }),
                validity_start: None,
                validity_end: Some(exp),
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let token = resp["result"].as_str().unwrap();

    let decomposed = ProofOfPossession::decompose_token(token).unwrap();
    assert_eq!(decomposed.header.algorithm, "EdDSA");
    assert_eq!(decomposed.header.r#type.as_deref(), Some("JWT"));
    assert_eq!(
        decomposed.header.key_id.as_deref(),
        Some(format!("{TEST_TDW_DID}#key-{}", key.id).as_str())
    );
    assert_eq!(decomposed.payload.issuer.as_deref(), Some(TEST_TDW_DID));
    let iat = decomposed.payload.issued_at.unwrap();
    assert!(iat >= before && iat <= one_core::clock::now_utc());
    assert_eq!(decomposed.payload.expires_at.unwrap(), exp);
    assert_eq!(decomposed.payload.custom.nonce, "Your Nonce");

    // only `iss`, `iat`, `exp` and `nonce` are part of the payload
    let raw_payload = token.split('.').nth(1).unwrap();
    let raw_payload: serde_json::Value =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(raw_payload, None).unwrap())
            .unwrap();
    let mut claims = raw_payload
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    claims.sort();
    assert_eq!(
        claims,
        vec![
            "exp".to_string(),
            "iat".to_string(),
            "iss".to_string(),
            "nonce".to_string()
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_swiyu_proof_of_possession_fail_on_other_did_method() {
    let (context, identifier, _key) = setup_did_identifier(
        None,
        "KEY",
        "did:key:z6MktdAr3iUReU7HsCf7JnoCjQ5urpKTxZSC49KnjEVsA5CA",
    )
    .await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "SWIYU_PROOF_OF_POSSESSION".to_string(),
                data: serde_json::json!({ "nonce": "Your Nonce" }),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_swiyu_proof_of_possession_fail_on_certificate_identifier() {
    let (context, _org, identifier, _cert, key) =
        TestContext::new_with_certificate_identifier(None).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: Some(key.id),
                issuer_certificate: None,
                signer: "SWIYU_PROOF_OF_POSSESSION".to_string(),
                data: serde_json::json!({ "nonce": "Your Nonce" }),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_swiyu_proof_of_possession_fail_on_missing_nonce() {
    let (context, identifier, _key) = setup_did_identifier(None, "TDW", TEST_TDW_DID).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "SWIYU_PROOF_OF_POSSESSION".to_string(),
                data: serde_json::json!({}),
                validity_start: None,
                validity_end: None,
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0332");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_swiyu_proof_of_possession_fail_on_validity_too_long() {
    let (context, identifier, _key) = setup_did_identifier(None, "TDW", TEST_TDW_DID).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "SWIYU_PROOF_OF_POSSESSION".to_string(),
                data: serde_json::json!({ "nonce": "Your Nonce" }),
                validity_start: None,
                validity_end: Some(one_core::clock::now_utc() + time::Duration::hours(1)),
            },
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0324");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_signature_swiyu_proof_of_possession_fail_on_missing_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["X509_CERTIFICATE_SIGN"], None).await;
    let (context, identifier, _key) = setup_did_identifier(Some(config), "TDW", TEST_TDW_DID).await;

    let resp = context
        .api
        .signatures
        .create(
            TestCreateSignatureRequest {
                issuer: identifier.id,
                issuer_key: None,
                issuer_certificate: None,
                signer: "SWIYU_PROOF_OF_POSSESSION".to_string(),
                data: serde_json::json!({ "nonce": "Your Nonce" }),
                validity_start: None,
                validity_end: None,
            },
            Some(token),
        )
        .await;

    assert_eq!(resp.status(), 403);
}
