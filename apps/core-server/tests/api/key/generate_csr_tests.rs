use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_generate_csr_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context.api.keys.generate_csr(&key.id.to_string()).await;
    assert_eq!(200, resp.status());

    let value = resp.json_value().await;

    let expected = r#"-----BEGIN CERTIFICATE REQUEST-----
MIHdMIGQAgEAMBwxDTALBgNVBAMMBHRlc3QxCzAJBgNVBAYMAkNIMCowBQYDK2Vw
AyEA3LOKxB5ik9WikgQmqNFtmuvNC0FMFFVXr6ATVoL+kT6gQTA/BgkqhkiG9w0B
CQ4xMjAwMAkGA1UdEQQCMAAwDAYDVR0PBAUDAwGAADAVBgNVHSUBAf8ECzAJBgco
gYxdBQECMAUGAytlcANBACmT9PixN3ak9UJeZ3X/VSDcD432y6p8s0AqIAsynlSQ
f9JK6JlEfqoUOyLFW5w/gtox9L0wan8dY5PrHtti0gU=
-----END CERTIFICATE REQUEST-----
"#;

    assert_eq!(expected, value["content"].as_str().unwrap())
}
