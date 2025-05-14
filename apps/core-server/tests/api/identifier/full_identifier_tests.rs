use validator::ValidateLength;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_identifier_success() {
    let (context, organisation, _, _, _) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, TestingKeyParams::default())
        .await;

    let result = context
        .api
        .identifiers
        .create_key_identifier("test-identifier", key.id, organisation.id)
        .await;

    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let identifier_id = resp["id"].as_str().unwrap().parse().unwrap();

    let result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;

    assert_eq!(resp["name"].as_str().unwrap(), "test-identifier");
    assert_eq!(resp["type"].as_str().unwrap(), "KEY");
    assert_eq!(resp["state"].as_str().unwrap(), "ACTIVE");
    assert!(!resp["isRemote"].as_bool().unwrap());
    assert_eq!(
        resp["organisationId"].as_str().unwrap(),
        organisation.id.to_string()
    );
    assert_eq!(resp["key"]["id"].as_str().unwrap(), key.id.to_string());

    let delete_resp = context.api.identifiers.delete(&identifier_id).await;
    assert_eq!(delete_resp.status(), 204);

    let already_deleted = context.api.identifiers.delete(&identifier_id).await;
    assert_eq!(already_deleted.status(), 404);
}

#[tokio::test]
async fn test_certificate_identifier() {
    let (context, organisation, ..) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    const CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDRjCCAuygAwIBAgIUcD+tZOWr65vnTr0OWGIVIzWOPscwCgYIKoZIzj0EAwIw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTI0MDgxMjA2MzMwMFoXDTI1MTExMDAwMDAwMFowRTELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxEjAQBgNVBAMM
CWxvY2FsLW9uZTAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+jToTZbglVNJl
E/Ulq+9fo4IByjCCAcYwDgYDVR0PAQH/BAQDAgeAMBUGA1UdJQEB/wQLMAkGByiB
jF0FAQIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTtGrCd4mBFUAA72lo0MhqY
vi23xTBaBgNVHR8EUzBRME+gTaBLhklodHRwczovL2NhLmRldi5tZGwtcGx1cy5j
b20vY3JsLzQwQ0QyMjU0N0YzODM0QzUyNkM1QzIyRTFBMjZDN0UyMDMzMjQ2Njgv
MIHKBggrBgEFBQcBAQSBvTCBujBbBggrBgEFBQcwAoZPaHR0cHM6Ly9jYS5kZXYu
bWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2
QzdFMjAzMzI0NjY4LmRlcjBbBggrBgEFBQcwAYZPaHR0cHM6Ly9jYS5kZXYubWRs
LXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIw
MzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1
cy5jb20wHQYDVR0OBBYEFBe08Q4Q6zU6zYq2bTwW5BCiIuYEMAoGCCqGSM49BAMC
A0gAMEUCIEQ8701fOGH/pskm/9G4EdzWRGY6jGOfHgoZc5nTBaCeAiEAsWoDCLnm
gEudfmbqXoiDCBYUmNabrVJo6GiBeczXVoU=
-----END CERTIFICATE-----
";

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, CERTIFICATE_PEM)
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
    assert_eq!(certificate["name"].as_str().unwrap(), "local-one");
    assert_eq!(certificate["state"].as_str().unwrap(), "ACTIVE");
    assert_eq!(
        certificate["x509Attributes"]["issuer"].as_str().unwrap(),
        "C=CH, L=Zurich, O=Procivis, OU=Procivis, CN=ca.dev.mdl-plus.com"
    );
    assert_eq!(
        certificate["x509Attributes"]["subject"].as_str().unwrap(),
        "C=CH, L=Zurich, O=Procivis, CN=local-one"
    );

    let certificate_id = certificate["id"].as_str().unwrap().parse().unwrap();
    let result = context.api.certificates.get(&certificate_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    resp["id"].assert_eq(&certificate_id);
}
