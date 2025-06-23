use rcgen::{
    CertificateParams, CertificateRevocationListParams, CrlDistributionPoint, RevokedCertParams,
};
use time::{Duration, OffsetDateTime};
use validator::ValidateLength;

use crate::fixtures::certificate::{create_ca_cert, create_cert, create_crl, ecdsa, eddsa};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_certificate_identifier_no_crl() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let ca_cert = create_ca_cert(CertificateParams::default(), eddsa::key());

    let cert = create_cert(
        CertificateParams::default(),
        ecdsa::key(),
        &ca_cert,
        eddsa::key(),
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

    let ca_cert = create_ca_cert(CertificateParams::default(), eddsa::key());

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    context.server_mock.fail_crl_download("1").await;

    let mut params = CertificateParams::new(["test.com".to_string()]).unwrap();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    let cert = create_cert(params, ecdsa::key(), &ca_cert, eddsa::key());

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

    let ca_params = CertificateParams::default();
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
    let ca_cert = create_ca_cert(ca_params, eddsa::key());
    let crl = create_crl(crl_params, &ca_cert, eddsa::key());

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    context.server_mock.crl_download("1", crl.der()).await;

    let mut params = CertificateParams::default();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    let cert = create_cert(params, ecdsa::key(), &ca_cert, eddsa::key());

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

    let ca_params = CertificateParams::default();
    let ca_cert = create_ca_cert(ca_params.to_owned(), eddsa::key());

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    let mut params = CertificateParams::default();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    params.serial_number = Some(vec![1].into());
    let cert = create_cert(params, ecdsa::key(), &ca_cert, eddsa::key());

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
            serial_number: cert.params().serial_number.to_owned().unwrap(),
            revocation_time: one_hour_before,
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: ca_params.key_identifier_method.to_owned(),
    };

    let crl = create_crl(crl_params, &ca_cert, eddsa::key());

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
