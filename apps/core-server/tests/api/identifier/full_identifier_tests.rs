use shared_types::IdentifierId;
use validator::ValidateLength;

use crate::api_oidc_tests::common::eddsa_key_2;
use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};
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
async fn test_identifier_did_disabled() {
    let config_changes = indoc::indoc! {"
    identifier:
        KEY:
            enabled: false
    "}
    .to_string();
    let (context, organisation) = TestContext::new_with_organisation(Some(config_changes)).await;

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

    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0227");
}

#[tokio::test]
async fn test_certificate_identifier() {
    let (context, organisation, ..) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    const CERTIFICATE_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----
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
-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIUQM0iVH84NMUmxcIuGibH4gMyRmgwCgYIKoZIzj0EAwQw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTIyMDExMjEyMDAwMFoXDTMyMDExMDEyMDAwMFowYjELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsM
CFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEaRFtZbpYHFlPgGyZCt6bGKS0hEekPVxiBHRXImo8
/NUR+czg+DI2KTE3ikRVNgq2rICatkvkV2jaM2frPEOl1qNmMGQwEgYDVR0TAQH/
BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFO0asJ3iYEVQADva
WjQyGpi+LbfFMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi+LbfFMAoGCCqG
SM49BAMEA0gAMEUCIQD9kfI800DOj76YsiW4lUNRZowH07j152M3UKHKEaIjUAIg
ZNINukb4SFKEC4A0qEKgpPEZM7/Vh5aNro+PQn3/rgA=
-----END CERTIFICATE-----
";

    let result = context
        .api
        .identifiers
        .create_certificate_identifier(
            "test-identifier",
            key.id,
            organisation.id,
            CERTIFICATE_CHAIN_PEM,
        )
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
    resp["organisationId"].assert_eq(&organisation.id);
}

#[tokio::test]
async fn test_certificate_identifier_expired() {
    let (context, organisation, ..) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // expired on May 15, 2025
    const CERTIFICATE_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDojCCA0egAwIBAgIUSBZZcT3ULQjGxYIrAngVPtVqpEcwCgYIKoZIzj0EAwIw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwNTE0MTIyNjAwWhcNMjUwNTE1MDAwMDAwWjA8MQswCQYD
VQQGEwJDSDERMA8GA1UECgwIUHJvY2l2aXMxGjAYBgNVBAMMEXRlc3QtY2VydC1l
eHBpcmVkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcd/LTtCQnat2XnDElumv
gQAM5ZcnUMVTkPig458C1yeJpCY9SCKvzQjZcIWqfb8o+p1YfQ/EzMII/xbe4/GV
QKOCAcowggHGMB8GA1UdIwQYMBaAFOUvSbZLyCmQ+Ut/E+xAz2rCovhwMAwGA1Ud
EwEB/wQCMAAwHQYDVR0OBBYEFMbE7SaA9sMKff8ChDE0V6YWnjRFMIHKBggrBgEF
BQcBAQSBvTCBujBbBggrBgEFBQcwAYZPaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMu
Y29tL29jc3AvMkNFOUQzRjQ5QjUyOEYwQ0QyOTM5NUQ0MEIyRTI1Q0MwNUUwQ0VD
My9jZXJ0LzBbBggrBgEFBQcwAoZPaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29t
L2lzc3Vlci8yQ0U5RDNGNDlCNTI4RjBDRDI5Mzk1RDQwQjJFMjVDQzA1RTBDRUMz
LmRlcjBaBgNVHR8EUzBRME+gTaBLhklodHRwczovL2NhLmRldi5tZGwtcGx1cy5j
b20vY3JsLzJDRTlEM0Y0OUI1MjhGMENEMjkzOTVENDBCMkUyNUNDMDVFMENFQzMv
MBUGA1UdJQEB/wQLMAkGByiBjF0FAQIwJgYDVR0SBB8wHYYbaHR0cHM6Ly9jYS5k
ZXYubWRsLXBsdXMuY29tMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNJADBG
AiEAw50YKy8XYwpvpadt58VE3lt4YOHYezHVTGk3s1oNI2UCIQD9z5w4K4bdZ4zn
RFpB/bZYDmXYFGIeqDDvskT/gdkUDw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC6jCCApCgAwIBAgIULOnT9JtSjwzSk5XUCy4lzAXgzsMwCgYIKoZIzj0EAwQw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwMzEzMTQzNzAwWhcNMzUwMzExMTQzNzAwWjCBljEcMBoG
A1UEAwwTY2EuZGV2Lm1kbC1wbHVzLmNvbTELMAkGA1UEBhMCQ0gxDzANBgNVBAcM
Blp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHjAcBgNVBAsMFUNlcnRpZmlj
YXRlIEF1dGhvcml0eTEiMCAGCSqGSIb3DQEJARYTc3VwcG9ydEBwcm9jaXZpcy5j
aDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC8hfYMdzhP87J1EnaaIInDNqGeb
PugTdzANq8kd2no4Xav/cyHsOVCe6FL7yYHButVR7xrmCbQip/0ctE0cdrejgbkw
gbYwDgYDVR0PAQH/BAQDAgEGMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jYS5k
ZXYubWRsLXBsdXMuY29tL2NybC8wHgYDVR0SBBcwFYITY2EuZGV2Lm1kbC1wbHVz
LmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTlL0m2S8gpkPlLfxPs
QM9qwqL4cDAfBgNVHSMEGDAWgBTlL0m2S8gpkPlLfxPsQM9qwqL4cDAKBggqhkjO
PQQDBANIADBFAiAwMs/rQEDwt0HbrAt4lvAwT3jrtqqR4BzZDQhqqh8zyAIhAKTY
qzmSNPsC3TZzs4uCBIsS3LKDZHCktmj3La1PCGSS
-----END CERTIFICATE-----
";

    let result = context
        .api
        .identifiers
        .create_certificate_identifier(
            "test-identifier",
            key.id,
            organisation.id,
            CERTIFICATE_CHAIN_PEM,
        )
        .await;

    assert_eq!(result.status(), 400);
    let resp = result.json_value().await;
    assert_eq!(resp["code"].as_str().unwrap(), "BR_0213");
}

#[tokio::test]
async fn test_certificate_identifier_invalid_signature() {
    let (context, organisation, ..) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // not matching parent certificate -> invalid signature
    const CERTIFICATE_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----
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
-----BEGIN CERTIFICATE-----
MIIC6jCCApCgAwIBAgIULOnT9JtSjwzSk5XUCy4lzAXgzsMwCgYIKoZIzj0EAwQw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwMzEzMTQzNzAwWhcNMzUwMzExMTQzNzAwWjCBljEcMBoG
A1UEAwwTY2EuZGV2Lm1kbC1wbHVzLmNvbTELMAkGA1UEBhMCQ0gxDzANBgNVBAcM
Blp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHjAcBgNVBAsMFUNlcnRpZmlj
YXRlIEF1dGhvcml0eTEiMCAGCSqGSIb3DQEJARYTc3VwcG9ydEBwcm9jaXZpcy5j
aDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC8hfYMdzhP87J1EnaaIInDNqGeb
PugTdzANq8kd2no4Xav/cyHsOVCe6FL7yYHButVR7xrmCbQip/0ctE0cdrejgbkw
gbYwDgYDVR0PAQH/BAQDAgEGMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jYS5k
ZXYubWRsLXBsdXMuY29tL2NybC8wHgYDVR0SBBcwFYITY2EuZGV2Lm1kbC1wbHVz
LmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTlL0m2S8gpkPlLfxPs
QM9qwqL4cDAfBgNVHSMEGDAWgBTlL0m2S8gpkPlLfxPsQM9qwqL4cDAKBggqhkjO
PQQDBANIADBFAiAwMs/rQEDwt0HbrAt4lvAwT3jrtqqR4BzZDQhqqh8zyAIhAKTY
qzmSNPsC3TZzs4uCBIsS3LKDZHCktmj3La1PCGSS
-----END CERTIFICATE-----
";

    let result = context
        .api
        .identifiers
        .create_certificate_identifier(
            "test-identifier",
            key.id,
            organisation.id,
            CERTIFICATE_CHAIN_PEM,
        )
        .await;

    assert_eq!(result.status(), 400);
    let resp = result.json_value().await;
    assert_eq!(resp["code"].as_str().unwrap(), "BR_0211");
}

#[tokio::test]
async fn test_identifier_filter_key_success() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_key_2().params)
        .await;

    let key_identifier_name = "test-key-identifier";
    let result = context
        .api
        .identifiers
        .create_key_identifier(key_identifier_name, key.id, organisation.id)
        .await;
    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let key_identifier_id: IdentifierId = resp["id"].as_str().unwrap().parse().unwrap();

    let did_key = context
        .db
        .keys
        .create(&organisation, eddsa_key_2().params)
        .await;
    let did_identifier_name = "test-did-identifier";
    let result = context
        .api
        .identifiers
        .create_did_identifier(did_identifier_name, did_key.id, organisation.id)
        .await;
    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let did_identifier_id: IdentifierId = resp["id"].as_str().unwrap().parse().unwrap();

    let result = context
        .api
        .identifiers
        .list_by_key_storage_type("INTERNAL", organisation.id)
        .await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    assert_eq!(2, resp["totalItems"]);
    assert_eq!(did_identifier_id.to_string(), resp["values"][0]["id"]);
    assert_eq!(did_identifier_name.to_string(), resp["values"][0]["name"]);
    assert_eq!(key_identifier_id.to_string(), resp["values"][1]["id"]);
    assert_eq!(key_identifier_name.to_string(), resp["values"][1]["name"]);

    let result = context.api.identifiers.get(&did_identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    assert_eq!(did_identifier_id.to_string(), resp["id"]);
    assert_eq!(did_identifier_name.to_string(), resp["name"]);
    assert_eq!(format!("did-{}", did_identifier_name), resp["did"]["name"]);

    let result = context
        .api
        .identifiers
        .list_by_key_storage_type("EXTERNAL", organisation.id)
        .await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    assert_eq!(0, resp["totalItems"]);
}
