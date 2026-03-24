use similar_asserts::assert_eq;

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
MIHUMIGHAgEAMBwxDTALBgNVBAMMBHRlc3QxCzAJBgNVBAYMAkNIMCowBQYDK2Vw
AyEASgRJyZPui8lPLXDEmCMPJr6NOhNluCVU0mUT9SWr71+gODA2BgkqhkiG9w0B
CQ4xKTAnMA4GA1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAUG
AytlcANBAH5XIT9a5FREeuQMHLJ90wBP1ggQsGlfp6arUIeqPZ9n3Dv+GDk823a5
jgiPcBHruzMhrcpjFDH7vLtvaDmsfww=
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
MIIBDzCBtgIBADAcMQ0wCwYDVQQDDAR0ZXN0MQswCQYDVQQGDAJDSDBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABHHfy07QkJ2rdl5wxJbpr4EADOWXJ1DFU5D4oOOf
AtcniaQmPUgir80I2XCFqn2/KPqdWH0PxMzCCP8W3uPxlUCgODA2BgkqhkiG9w0B
CQ4xKTAnMA4GA1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAoG
CCqGSM49BAMCA0gAMEUCIAgJPW2/WNgmftvVENWniwYI/beXxkvmgzsaZJo/WVxv
AiEAlj3K3cDaSKXqvMZf11p9fZK7mLUSf0bzlbPKWdIuQDk=
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
MIGgMFQCAQAwADAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+jToTZbglVNJl
E/Ulq+9foCEwHwYJKoZIhvcNAQkOMRIwEDAOBgNVHQ8BAf8EBAMCB4AwBQYDK2Vw
A0EA51Drn3m5rhmagKmShYhiPj1yu5Yul2MTJ4XrGF1jBjriMoHvpkoeVp2rYoLO
Jqoes8/uLKBLmVisv5rmxJbGDg==
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_generate_ca_csr_for_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context.api.keys.generate_ca_csr(&key.id.to_string()).await;
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
