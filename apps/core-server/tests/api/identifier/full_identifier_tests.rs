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
#[ignore] // disabled for now, the CA is producing outdated CRLs
async fn test_certificate_identifier() {
    let (context, organisation, ..) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // https://ca.dev.mdl-plus.com/admin/django_ca/certificate/85574
    const CERTIFICATE_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDgTCCAyegAwIBAgIUG7aF+voywSo7piE7xPFdY7q9b2AwCgYIKoZIzj0EAwIw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwNTIyMDk0NzAwWhcNMzIwMTAxMDAwMDAwWjAcMRowGAYD
VQQDDBFFQ0RTQSBjZXJ0IHRlc3QgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BHHfy07QkJ2rdl5wxJbpr4EADOWXJ1DFU5D4oOOfAtcniaQmPUgir80I2XCFqn2/
KPqdWH0PxMzCCP8W3uPxlUCjggHKMIIBxjAfBgNVHSMEGDAWgBTwRW4F4T4leovc
Pb2ViJ4f4ydmmTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTGxO0mgPbDCn3/AoQx
NFemFp40RTCBygYIKwYBBQUHAQEEgb0wgbowWwYIKwYBBQUHMAGGT2h0dHBzOi8v
Y2EuZGV2Lm1kbC1wbHVzLmNvbS9vY3NwLzBGNDgzRkQzQzYxMkY4NDhCMkM0REND
QkY4ODlBNkVBOTgwRjUzNDAvY2VydC8wWwYIKwYBBQUHMAKGT2h0dHBzOi8vY2Eu
ZGV2Lm1kbC1wbHVzLmNvbS9pc3N1ZXIvMEY0ODNGRDNDNjEyRjg0OEIyQzREQ0NC
Rjg4OUE2RUE5ODBGNTM0MC5kZXIwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9j
YS5kZXYubWRsLXBsdXMuY29tL2NybC8wRjQ4M0ZEM0M2MTJGODQ4QjJDNERDQ0JG
ODg5QTZFQTk4MEY1MzQwLzAVBgNVHSUBAf8ECzAJBgcogYxdBQECMCYGA1UdEgQf
MB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAOBgNVHQ8BAf8EBAMCB4Aw
CgYIKoZIzj0EAwIDSAAwRQIgYM56ebU1iCzxJ70ATo2ww3sJ/rMxT1pqR9OEmUDz
HlICIQCerzJ59aEl0faphLxoWlmeYFa7JflJIvEFRHdPdXdOpQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC6TCCApCgAwIBAgIUD0g/08YS+EiyxNzL+Imm6pgPU0AwCgYIKoZIzj0EAwIw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwNTIyMDcxNTAwWhcNMzUwNTIwMDcxNTAwWjCBljEcMBoG
A1UEAwwTY2EuZGV2Lm1kbC1wbHVzLmNvbTELMAkGA1UEBhMCQ0gxDzANBgNVBAcM
Blp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHjAcBgNVBAsMFUNlcnRpZmlj
YXRlIEF1dGhvcml0eTEiMCAGCSqGSIb3DQEJARYTc3VwcG9ydEBwcm9jaXZpcy5j
aDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBirJpjRvYLhQIxzvPnyqOVa/CAI
QbI0F8CGyQSzrb4iXLBp5+5WkjAN5oy4sJB8vpEslrBKDpsxqALFLrzUTi2jgbkw
gbYwDgYDVR0PAQH/BAQDAgEGMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jYS5k
ZXYubWRsLXBsdXMuY29tL2NybC8wHgYDVR0SBBcwFYITY2EuZGV2Lm1kbC1wbHVz
LmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTwRW4F4T4leovcPb2V
iJ4f4ydmmTAfBgNVHSMEGDAWgBTwRW4F4T4leovcPb2ViJ4f4ydmmTAKBggqhkjO
PQQDAgNHADBEAiBfV0E26uDYnAgkVdniOTrZhtDeT2XeKGanHb+NeaBKFwIgIrDI
ednLQ73tVDVC3JN0GnejhHyFSYlpFWz831np/7M=
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
    assert_eq!(certificate["name"].as_str().unwrap(), "ECDSA cert test 3");
    assert_eq!(certificate["state"].as_str().unwrap(), "ACTIVE");
    assert_eq!(
        certificate["x509Attributes"]["issuer"].as_str().unwrap(),
        "CN=ca.dev.mdl-plus.com, C=CH, L=Zurich, O=Procivis AG, OU=Certificate Authority, Email=support@procivis.ch"
    );
    assert_eq!(
        certificate["x509Attributes"]["subject"].as_str().unwrap(),
        "CN=ECDSA cert test 3"
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

    // https://ca.dev.mdl-plus.com/admin/django_ca/certificate/79584
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
#[ignore] // disabled for now, the CA is producing outdated CRLs
async fn test_certificate_identifier_revoked() {
    let (context, organisation, ..) = TestContext::new_with_did(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // https://ca.dev.mdl-plus.com/admin/django_ca/certificate/85680
    const CERTIFICATE_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDgTCCAyigAwIBAgIUQz4cmvS7/pSd+MNJ7piTC63e4uowCgYIKoZIzj0EAwIw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwNTIyMTEzOTAwWhcNMjYwNTIyMDAwMDAwWjAdMRswGQYD
VQQDDBJFQ0RTQSByZXZva2VkIHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ4mkJj1IIq/NCNlwhap9
vyj6nVh9D8TMwgj/Ft7j8ZVAo4IByjCCAcYwHwYDVR0jBBgwFoAU8EVuBeE+JXqL
3D29lYieH+MnZpkwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUxsTtJoD2wwp9/wKE
MTRXphaeNEUwgcoGCCsGAQUFBwEBBIG9MIG6MFsGCCsGAQUFBzABhk9odHRwczov
L2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC8wRjQ4M0ZEM0M2MTJGODQ4QjJDNERD
Q0JGODg5QTZFQTk4MEY1MzQwL2NlcnQvMFsGCCsGAQUFBzAChk9odHRwczovL2Nh
LmRldi5tZGwtcGx1cy5jb20vaXNzdWVyLzBGNDgzRkQzQzYxMkY4NDhCMkM0REND
QkY4ODlBNkVBOTgwRjUzNDAuZGVyMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8v
Y2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvMEY0ODNGRDNDNjEyRjg0OEIyQzREQ0NC
Rjg4OUE2RUE5ODBGNTM0MC8wFQYDVR0lAQH/BAswCQYHKIGMXQUBAjAmBgNVHRIE
HzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wDgYDVR0PAQH/BAQDAgeA
MAoGCCqGSM49BAMCA0cAMEQCICzjzL16g4tQ5p5/FRGslOCEVzJbzKUcRuA71x0X
3/2fAiA0zxhuWlCKdibXwF1IcvXOgpUEhiwkTIE9TnPw8pFOFA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC6TCCApCgAwIBAgIUD0g/08YS+EiyxNzL+Imm6pgPU0AwCgYIKoZIzj0EAwIw
gZYxHDAaBgNVBAMME2NhLmRldi5tZGwtcGx1cy5jb20xCzAJBgNVBAYTAkNIMQ8w
DQYDVQQHDAZadXJpY2gxFDASBgNVBAoMC1Byb2NpdmlzIEFHMR4wHAYDVQQLDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEWE3N1cHBvcnRAcHJv
Y2l2aXMuY2gwHhcNMjUwNTIyMDcxNTAwWhcNMzUwNTIwMDcxNTAwWjCBljEcMBoG
A1UEAwwTY2EuZGV2Lm1kbC1wbHVzLmNvbTELMAkGA1UEBhMCQ0gxDzANBgNVBAcM
Blp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHjAcBgNVBAsMFUNlcnRpZmlj
YXRlIEF1dGhvcml0eTEiMCAGCSqGSIb3DQEJARYTc3VwcG9ydEBwcm9jaXZpcy5j
aDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBirJpjRvYLhQIxzvPnyqOVa/CAI
QbI0F8CGyQSzrb4iXLBp5+5WkjAN5oy4sJB8vpEslrBKDpsxqALFLrzUTi2jgbkw
gbYwDgYDVR0PAQH/BAQDAgEGMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jYS5k
ZXYubWRsLXBsdXMuY29tL2NybC8wHgYDVR0SBBcwFYITY2EuZGV2Lm1kbC1wbHVz
LmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTwRW4F4T4leovcPb2V
iJ4f4ydmmTAfBgNVHSMEGDAWgBTwRW4F4T4leovcPb2ViJ4f4ydmmTAKBggqhkjO
PQQDAgNHADBEAiBfV0E26uDYnAgkVdniOTrZhtDeT2XeKGanHb+NeaBKFwIgIrDI
ednLQ73tVDVC3JN0GnejhHyFSYlpFWz831np/7M=
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
    assert_eq!(resp["code"].as_str().unwrap(), "BR_0212");
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
