use core_server::endpoint::key::dto::KeyGenerateCSRRequestProfileRest;
use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::api_clients::keys::CsrParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};

#[tokio::test(flavor = "multi_thread")]
async fn test_generate_mdl_csr_for_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context
        .api
        .keys
        .generate_csr(
            &key.id.to_string(),
            KeyGenerateCSRRequestProfileRest::Mdl,
            Default::default(),
        )
        .await;
    assert_eq!(201, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MIHdMIGQAgEAMBwxDTALBgNVBAMMBHRlc3QxCzAJBgNVBAYMAkNIMCowBQYDK2Vw
AyEASgRJyZPui8lPLXDEmCMPJr6NOhNluCVU0mUT9SWr71+gQTA/BgkqhkiG9w0B
CQ4xMjAwMA4GA1UdDwEB/wQEAwIHgDAeBgNVHSUBAf8EFDASBgcogYxdBQECBgco
gbU0BAECMAUGAytlcANBAOHJGXnWvyL7+3jfTF0J/4+FWeFv3j+owT/KbkSLENT2
RhyRwZCJe/ncC06JHw3r1cT5zMVM0yrz1KwUjhHkQAI=
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_generate_mdl_csr_for_ecdsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let resp = context
        .api
        .keys
        .generate_csr(
            &key.id.to_string(),
            KeyGenerateCSRRequestProfileRest::Mdl,
            Default::default(),
        )
        .await;
    assert_eq!(201, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MIIBGDCBvwIBADAcMQ0wCwYDVQQDDAR0ZXN0MQswCQYDVQQGDAJDSDBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABHHfy07QkJ2rdl5wxJbpr4EADOWXJ1DFU5D4oOOf
AtcniaQmPUgir80I2XCFqn2/KPqdWH0PxMzCCP8W3uPxlUCgQTA/BgkqhkiG9w0B
CQ4xMjAwMA4GA1UdDwEB/wQEAwIHgDAeBgNVHSUBAf8EFDASBgcogYxdBQECBgco
gbU0BAECMAoGCCqGSM49BAMCA0gAMEUCIQDTjm/YTnS5SaopsgYrKpQISodz4ZM0
DPFUZKU5qSZMugIgKBLekrvQInbWtfrrK/r0MO0kz9OgwqSAH+cuI4yBPSE=
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_generate_generic_csr_for_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context
        .api
        .keys
        .generate_csr(
            &key.id.to_string(),
            KeyGenerateCSRRequestProfileRest::Generic,
            CsrParams {
                subject: Some(json!({})),
                subject_alternative_name: Some(json!({
                    "DNSName": ["*.procivis.ch"]
                })),
            },
        )
        .await;
    assert_eq!(201, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MIG9MHECAQAwADAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+jToTZbglVNJl
E/Ulq+9foD4wPAYJKoZIhvcNAQkOMS8wLTAOBgNVHQ8BAf8EBAMCB4AwGwYDVR0R
AQH/BBEwD4INKi5wcm9jaXZpcy5jaDAFBgMrZXADQQBVcehDAOrDwrglsYOGH+ZZ
ugPFYjvqaNMtbPZ+py3CBzuttWme+MaQFshTyJ6A5WH2PW2gSMK+A2kiRM8sh1IL
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_generate_ca_csr_for_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context
        .api
        .keys
        .generate_csr(
            &key.id.to_string(),
            KeyGenerateCSRRequestProfileRest::Ca,
            Default::default(),
        )
        .await;
    assert_eq!(201, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MIG8MHACAQAwHDENMAsGA1UEAwwEdGVzdDELMAkGA1UEBgwCQ0gwKjAFBgMrZXAD
IQBKBEnJk+6LyU8tcMSYIw8mvo06E2W4JVTSZRP1JavvX6AhMB8GCSqGSIb3DQEJ
DjESMBAwDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBAAnM4QZv1Z+JTxGOgJpl7SAF
1rXxKIQLD9QROssAr+Sm/Nn69GwZVOPsmVPyqm2uBYyPUK9mzjuDYsGGPOsmWgU=
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}
