use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_generate_mdl_csr_for_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context.api.keys.generate_mdl_csr(&key.id.to_string()).await;
    assert_eq!(201, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MIHdMIGQAgEAMBwxDTALBgNVBAMMBHRlc3QxCzAJBgNVBAYMAkNIMCowBQYDK2Vw
AyEASgRJyZPui8lPLXDEmCMPJr6NOhNluCVU0mUT9SWr71+gQTA/BgkqhkiG9w0B
CQ4xMjAwMAkGA1UdEQQCMAAwDAYDVR0PBAUDAwGAADAVBgNVHSUBAf8ECzAJBgco
gYxdBQECMAUGAytlcANBAJXegLNLpWK+j5H3Vn9+QIUsTLqsM4aXS3PnoCt3x6qS
sMe0CTXdZ9fH85I+9x5xOUAakrR0vZuLYD4GOMeN7QY=
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_generate_mdl_csr_for_ecdsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let resp = context.api.keys.generate_mdl_csr(&key.id.to_string()).await;
    assert_eq!(201, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MIIBETCBvwIBADAcMQ0wCwYDVQQDDAR0ZXN0MQswCQYDVQQGDAJDSDBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABHHfy07QkJ2rdl5wxJbpr4EADOWXJ1DFU5D4oOOf
AtcniaQmPUgir80I2XCFqn2/KPqdWH0PxMzCCP8W3uPxlUCgQTA/BgkqhkiG9w0B
CQ4xMjAwMAkGA1UdEQQCMAAwDAYDVR0PBAUDAwGAADAVBgNVHSUBAf8ECzAJBgco
gYxdBQECMAoGCCqGSM49BAMCA0EAVCW8fAbq+Uzksv7fxxJa+y5FpAYxKVC8JbYf
BHUnuBHPrlA4lzOemugfbKu6zCFvjM+z4Gfrj5gZJGpXEPQHLg==
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .generate_generic_csr(&key.id.to_string())
        .await;
    assert_eq!(201, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MH8wMwIBADAAMCowBQYDK2VwAyEASgRJyZPui8lPLXDEmCMPJr6NOhNluCVU0mUT
9SWr71+gADAFBgMrZXADQQD1zJ7xBpJX0xG0O1nbqMgJ54LrtndQru1F5P4bNOAq
SI5aYyAmSqLvuy8x7fsCmJ7AdsUI7lrDFUJ0Ivi3/GsH
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}
