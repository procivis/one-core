use one_core::model::did::DidType;
use serde_json::json;

use crate::fixtures::TestingKeyParams;
use crate::utils::api_clients::dids::DidKeys;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{eddsa_testing_params, es256_testing_params};
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_did_key_es256_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "KEY",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "KEY");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:key:zDn"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_key_dilithium_failure_incapable() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let test_params = TestingKeyParams {
        key_type: Some("Dilithium".to_owned()), // Not capable
        storage_type: Some("INTERNAL".to_string()),
        ..Default::default()
    };

    let key = context.db.keys.create(&organisation, test_params).await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "KEY",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_did_key_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "KEY",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "KEY");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:key:z6Mk"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_fail_to_create_did_key_to_much_keys() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key1 = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    let key2 = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::all(vec![key1.id.into(), key2.id.into()]),
            "KEY",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0030", resp.error_code().await);
}

#[tokio::test]
async fn test_create_did_web_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "WEB",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "WEB");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:web"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_web_mixed_keys() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key1 = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    let key2 = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys {
                assertion_method: vec![key1.id.into(), key2.id.into()],
                authentication: vec![key1.id.into(), key2.id.into()],
                capability_delegation: vec![key1.id.into()],
                capability_invocation: vec![key1.id.into()],
                key_agreement: vec![key1.id.into()],
            },
            "WEB",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "WEB");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:web"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 7);
}

#[tokio::test]
async fn test_create_did_jwk_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "JWK",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "JWK");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:jwk"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_with_same_name_in_different_organisations() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did().await;

    let organisation1 = context.db.organisations.create().await;
    let key = context
        .db
        .keys
        .create(&organisation1, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation1.id,
            DidKeys::single(key.id.into()),
            "JWK",
            &did.name,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_did_with_same_name_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key1 = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let key2 = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key1.id.into()),
            "JWK",
            "test",
            None,
        )
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key2.id.into()),
            "JWK",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_to_create_did_with_same_value_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "JWK",
            "test 1",
            None,
        )
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "JWK",
            "test 2",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_did_with_same_value_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let organisation1 = context.db.organisations.create().await;
    let key = context
        .db
        .keys
        .create(&organisation1, eddsa_testing_params())
        .await;

    // WHEN
    let resp1 = context
        .api
        .dids
        .create(
            organisation1.id,
            DidKeys::single(key.id.into()),
            "JWK",
            "test 1",
            None,
        )
        .await;

    let resp2 = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "JWK",
            "test 2",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp1.status(), 201);
    assert_eq!(resp2.status(), 201);
}

#[tokio::test]
async fn test_create_did_mdl_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    // obtained from https://ca.dev.mdl-plus.com/admin for the MDL-CA(iacaCertficate in config) for the CSR obtained from eddsa_testing_params() key
    let signed_csr = "-----BEGIN CERTIFICATE-----
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

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "MDL",
            "test-mdl",
            Some(json!({
                "certificate": signed_csr,
            })),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "MDL");
    assert_eq!(did.did_type, DidType::Local);

    assert!(did.did.as_str().starts_with("did:mdl:certificate"));

    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_mdl_es256_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    // obtained from https://ca.dev.mdl-plus.com/admin for the MDL-CA(iacaCertficate in config) for the CSR obtained from eddsa_testing_params() key
    let signed_csr = "-----BEGIN CERTIFICATE-----
MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIw
YjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2
aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMu
Y29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMC
Q0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNV
BAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMB
BwMiAAJx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ6OCAeswggHnMA4G
A1UdDwEB/wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBP
oE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdG
MzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbsw
gbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vl
ci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBa
BggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENE
MjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1Ud
EgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0
ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3/AoQxNFem
Fp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s/EI
1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg==
-----END CERTIFICATE-----
";

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id.into()),
            "MDL",
            "test-mdl",
            Some(json!({
                "certificate": signed_csr,
            })),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "MDL");
    assert_eq!(did.did_type, DidType::Local);

    assert!(did.did.as_str().starts_with("did:mdl:certificate"));

    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}
