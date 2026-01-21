use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CustomExtension, IsCa, KeyUsagePurpose, RevokedCertParams, SerialNumber,
};
use serde_json::json;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use validator::ValidateLength;

use crate::fixtures::certificate::{create_ca_cert, create_cert, create_crl, ecdsa, eddsa};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_certificate_authority_identifier_no_crl() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let mut cert_params = CertificateParams::default();
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = create_cert(&mut cert_params, ecdsa::Key, &ca_issuer, &ca_params);

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    // when
    let result = context
        .api
        .identifiers
        .create_certificate_authority_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    // then
    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let identifier_id = resp["id"].as_str().unwrap().parse().unwrap();

    let result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;

    assert_eq!(resp["name"].as_str().unwrap(), "test-identifier");
    assert_eq!(resp["type"].as_str().unwrap(), "CA");
    assert_eq!(resp["state"].as_str().unwrap(), "ACTIVE");
    assert!(!resp["isRemote"].as_bool().unwrap());
    assert_eq!(
        resp["organisationId"].as_str().unwrap(),
        organisation.id.to_string()
    );
    assert_eq!(
        resp["certificateAuthorities"].as_array().length().unwrap(),
        1
    );

    let certificate = &resp["certificateAuthorities"][0];
    assert_eq!(certificate["name"].as_str().unwrap(), "test cert");
    assert_eq!(certificate["state"].as_str().unwrap(), "ACTIVE");
    assert_eq!(
        certificate["x509Attributes"]["issuer"].as_str().unwrap(),
        "CN=CA cert"
    );
    assert_eq!(
        certificate["x509Attributes"]["subject"].as_str().unwrap(),
        "CN=test cert"
    );
    assert!(
        certificate["x509Attributes"]["extensions"]
            .as_array()
            .unwrap()
            .contains(&json!({
                "critical": true,
                "oid": "2.5.29.19",
                "value": "Certificate Authority: true",
            }))
    );

    let certificate_id = certificate["id"].as_str().unwrap().parse().unwrap();
    let result = context.api.certificates.get(&certificate_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    resp["id"].assert_eq(&certificate_id);
    resp["organisationId"].assert_eq(&organisation.id);
}

#[tokio::test]
async fn test_create_certificate_authority_incorrect_key_usage() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let mut cert_params = CertificateParams::default();
    cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let cert = create_cert(&mut cert_params, ecdsa::Key, &ca_issuer, &ca_params);

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    // when
    let result = context
        .api
        .identifiers
        .create_certificate_authority_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0249");
}

#[tokio::test]
async fn test_create_certificate_authority_missing_ca_extension() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let mut cert_params = CertificateParams::default();
    cert_params.is_ca = IsCa::NoCa;
    cert_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = create_cert(&mut cert_params, ecdsa::Key, &ca_issuer, &ca_params);

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    // when
    let result = context
        .api
        .identifiers
        .create_certificate_authority_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0244");
}

#[tokio::test]
async fn test_create_certificate_authority_missing_chain_and_self_signed_fields() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // when
    let result = context
        .api
        .identifiers
        .try_create_certificate_authority_identifier("test-identifier", key.id, organisation.id)
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0331");
}

#[tokio::test]
async fn test_create_certificate_identifier_no_crl() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let cert = create_cert(
        &mut CertificateParams::default(),
        ecdsa::Key,
        &ca_issuer,
        &ca_params,
    );

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 201);
}

#[tokio::test]
async fn test_create_certificate_identifier_crl_not_available() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    context.server_mock.fail_crl_download("1").await;

    let mut params = CertificateParams::new(["test.com".to_string()]).unwrap();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    let cert = create_cert(&mut params, ecdsa::Key, &ca_issuer, &ca_params);

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    // revocation error
    assert_eq!(result.status(), 500);
    assert_eq!(result.error_code().await, "BR_0101");
}

#[tokio::test]
async fn test_create_certificate_identifier_with_crl() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let crl_params = CertificateRevocationListParams {
        this_update: OffsetDateTime::now_utc()
            .checked_sub(Duration::hours(1))
            .unwrap(),
        next_update: OffsetDateTime::now_utc()
            .checked_add(Duration::hours(24))
            .unwrap(),
        crl_number: vec![0].into(),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: ca_params.key_identifier_method.to_owned(),
    };
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);
    let crl = create_crl(&crl_params, ca_params.clone(), eddsa::Key);

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    context.server_mock.crl_download("1", crl.der()).await;

    let mut params = CertificateParams::default();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    let cert = create_cert(&mut params, ecdsa::Key, &ca_issuer, &ca_params);

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let identifier_id = resp["id"].as_str().unwrap().parse().unwrap();

    let result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;

    assert_eq!(resp["name"].as_str().unwrap(), "test-identifier");
    assert_eq!(resp["type"].as_str().unwrap(), "CERTIFICATE");
    assert_eq!(resp["state"].as_str().unwrap(), "ACTIVE");
    assert!(!resp["isRemote"].as_bool().unwrap());
    assert_eq!(
        resp["organisationId"].as_str().unwrap(),
        organisation.id.to_string()
    );
    assert_eq!(resp["certificates"].as_array().length().unwrap(), 1);

    let certificate = &resp["certificates"][0];
    assert_eq!(certificate["name"].as_str().unwrap(), "test cert");
    assert_eq!(certificate["state"].as_str().unwrap(), "ACTIVE");
    assert_eq!(
        certificate["x509Attributes"]["issuer"].as_str().unwrap(),
        "CN=CA cert"
    );
    assert_eq!(
        certificate["x509Attributes"]["subject"].as_str().unwrap(),
        "CN=test cert"
    );

    let certificate_id = certificate["id"].as_str().unwrap().parse().unwrap();
    let result = context.api.certificates.get(&certificate_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    resp["id"].assert_eq(&certificate_id);
    resp["organisationId"].assert_eq(&organisation.id);
}

#[tokio::test]
async fn test_create_certificate_identifier_with_crl_revoked() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    let mut params = CertificateParams::default();
    params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    let serial_number: SerialNumber = vec![1].into();
    params.serial_number = Some(serial_number.clone());
    let cert = create_cert(&mut params, ecdsa::Key, &ca_issuer, &ca_params);

    let one_hour_before = OffsetDateTime::now_utc()
        .checked_sub(Duration::hours(1))
        .unwrap();
    let crl_params = CertificateRevocationListParams {
        this_update: one_hour_before,
        next_update: OffsetDateTime::now_utc()
            .checked_add(Duration::hours(24))
            .unwrap(),
        crl_number: vec![0].into(),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number,
            revocation_time: one_hour_before,
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: ca_params.key_identifier_method.to_owned(),
    };

    let crl = create_crl(&crl_params, params, eddsa::Key);

    context.server_mock.crl_download("1", crl.der()).await;

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0212");
}

#[tokio::test]
async fn test_create_certificate_identifier_cert_already_exists() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    let cert = create_cert(
        &mut CertificateParams::default(),
        ecdsa::Key,
        &ca_issuer,
        &ca_params,
    );

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 201);

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier2", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0247");
}

#[tokio::test]
async fn test_create_certificate_identifier_unknown_critical_extension() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let mut ca_params = CertificateParams::default();
    let mut custom_extension = CustomExtension::new_acme_identifier(&[0; 32]);
    custom_extension.set_criticality(true);
    ca_params.custom_extensions = vec![custom_extension];
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let (ca_cert, _) = create_ca_cert(&mut ca_params, &eddsa::Key);
    let chain = format!("{}{}", ca_cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0248");
}

#[tokio::test]
async fn test_create_certificate_identifier_ca_incorrect_key_usage() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // CA with incorrect key usage (missing KeyCertSign)
    let mut ca_params = CertificateParams::default();
    ca_params.key_usages = vec![KeyUsagePurpose::DigitalSignature]; // Missing KeyCertSign
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    // Leaf certificate
    let mut leaf_params = CertificateParams::default();
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf_cert = create_cert(&mut leaf_params, ecdsa::Key, &ca_issuer, &ca_params);

    let chain = format!("{}{}", leaf_cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0249");
}

#[tokio::test]
async fn test_create_certificate_identifier_missing_digital_signature() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // CA with proper key usage
    let mut ca_params = CertificateParams::default();
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);

    // End-entity certificate missing DigitalSignature
    let mut cert_params = CertificateParams::default();
    cert_params.key_usages = vec![KeyUsagePurpose::KeyEncipherment]; // Missing DigitalSignature
    let cert = create_cert(&mut cert_params, ecdsa::Key, &ca_issuer, &ca_params);

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0249"); // Key usage violation
}
