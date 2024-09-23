use core::panic;
use std::str::FromStr;

use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use serde_json::json;
use shared_types::{CredentialSchemaId, DidValue};

use crate::fixtures::{TestingDidParams, TestingKeyParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{eddsa_testing_params, es256_testing_params};

pub(super) async fn prepare_dids_for_mdoc(
    context: &TestContext,
    organisation: &Organisation,
    local_key_params: TestKey,
    remote_key_params: TestKey,
) -> (Did, Did, Key) {
    let local_key = context
        .db
        .keys
        .create(organisation, local_key_params.params)
        .await;

    let did_value: DidValue = match local_key.key_type.as_str() {
        "EDDSA" => "did:mdl:certificate:MIIDRjCCAuygAwIBAgIUcD-tZOWr65vnTr0OWGIVIzWOPscwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDgxMjA2MzMwMFoXDTI1MTExMDAwMDAwMFowRTELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxEjAQBgNVBAMMCWxvY2FsLW9uZTAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya-jToTZbglVNJlE_Ulq-9fo4IByjCCAcYwDgYDVR0PAQH_BAQDAgeAMBUGA1UdJQEB_wQLMAkGByiBjF0FAQIwDAYDVR0TAQH_BAIwADAfBgNVHSMEGDAWgBTtGrCd4mBFUAA72lo0MhqYvi23xTBaBgNVHR8EUzBRME-gTaBLhklodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20vY3JsLzQwQ0QyMjU0N0YzODM0QzUyNkM1QzIyRTFBMjZDN0UyMDMzMjQ2NjgvMIHKBggrBgEFBQcBAQSBvTCBujBbBggrBgEFBQcwAoZPaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBbBggrBgEFBQcwAYZPaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL29jc3AvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC9jZXJ0LzAmBgNVHRIEHzAdhhtodHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20wHQYDVR0OBBYEFBe08Q4Q6zU6zYq2bTwW5BCiIuYEMAoGCCqGSM49BAMCA0gAMEUCIEQ8701fOGH_pskm_9G4EdzWRGY6jGOfHgoZc5nTBaCeAiEAsWoDCLnmgEudfmbqXoiDCBYUmNabrVJo6GiBeczXVoU",
        "ES256" => "did:mdl:certificate:MIIDhzCCAyygAwIBAgIUahQKX8KQ86zDl0g9Wy3kW6oxFOQwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI0MDUxNDA5MDAwMFoXDTI4MDIyOTAwMDAwMFowVTELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxHzAdBgNVBAMMFnRlc3QuZXMyNTYucHJvY2l2aXMuY2gwOTATBgcqhkjOPQIBBggqhkjOPQMBBwMiAAJx38tO0JCdq3ZecMSW6a-BAAzllydQxVOQ-KDjnwLXJ6OCAeswggHnMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMAwGA1UdEwEB_wQCMAAwHwYDVR0jBBgwFoAU7RqwneJgRVAAO9paNDIamL4tt8UwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cHM6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2NybC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LzCByAYIKwYBBQUHAQEEgbswgbgwWgYIKwYBBQUHMAKGTmh0dHA6Ly9jYS5kZXYubWRsLXBsdXMuY29tL2lzc3Vlci80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4LmRlcjBaBggrBgEFBQcwAYZOaHR0cDovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAhBgNVHREEGjAYghZ0ZXN0LmVzMjU2LnByb2NpdmlzLmNoMB0GA1UdDgQWBBTGxO0mgPbDCn3_AoQxNFemFp40RTAKBggqhkjOPQQDAgNJADBGAiEAiRmxICo5Gxa4dlcK0qeyGDqyBOA9s_EI1V1b4KfIsl0CIQCHu0eIGECUJIffrjmSc7P6YnQfxgocBUko7nra5E0Lhg",
        other => panic!("did:mdl:certificate is not supported for kty: {other}"),
    }
    .parse()
    .unwrap();

    let local_did = context
        .db
        .dids
        .create(
            organisation,
            TestingDidParams {
                did_type: Some(DidType::Local),
                did_method: Some("MDL".to_owned()),
                did: Some(did_value),
                ..key_to_did_params(Some(&local_key), &local_key_params.multibase)
            },
        )
        .await;

    let remote_did = context
        .db
        .dids
        .create(
            organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..key_to_did_params(None, &remote_key_params.multibase)
            },
        )
        .await;

    (local_did, remote_did, local_key)
}

pub(super) async fn prepare_dids(
    context: &TestContext,
    organisation: &Organisation,
    local_key_params: Option<TestKey>,
    remote_key_params: Option<TestKey>,
) -> (Option<Did>, Option<Did>, Option<Key>) {
    let (local_did, local_key) = if let Some(local_key_params) = local_key_params {
        let local_key = context
            .db
            .keys
            .create(organisation, local_key_params.params)
            .await;
        (
            Some(
                context
                    .db
                    .dids
                    .create(
                        organisation,
                        TestingDidParams {
                            did_type: Some(DidType::Local),
                            ..key_to_did_params(Some(&local_key), &local_key_params.multibase)
                        },
                    )
                    .await,
            ),
            Some(local_key),
        )
    } else {
        (None, None)
    };

    let remote_did = if let Some(remote_key_params) = remote_key_params {
        Some(
            context
                .db
                .dids
                .create(
                    organisation,
                    TestingDidParams {
                        did_type: Some(DidType::Remote),
                        ..key_to_did_params(None, &remote_key_params.multibase)
                    },
                )
                .await,
        )
    } else {
        None
    };

    (local_did, remote_did, local_key)
}

pub(super) fn key_to_did_params(key: Option<&Key>, multibase: &str) -> TestingDidParams {
    TestingDidParams {
        did_method: Some("KEY".to_string()),
        did: Some(DidValue::from_str(&format!("did:key:{multibase}",)).unwrap()),
        keys: key.map(|key| {
            vec![
                RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                },
            ]
        }),
        ..Default::default()
    }
}

#[derive(Clone)]
pub(super) struct TestKey {
    multibase: String,
    params: TestingKeyParams,
}

pub(super) fn eddsa_key_1() -> TestKey {
    TestKey {
        multibase: "z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB".to_string(),
        params: TestingKeyParams {
            key_type: Some("EDDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                247, 48, 105, 26, 32, 134, 117, 181, 204, 194, 200, 75, 150, 16, 179, 22, 25, 85,
                252, 36, 83, 75, 3, 227, 191, 61, 55, 14, 149, 78, 206, 62,
            ]),
            key_reference: Some(vec![
                212, 80, 75, 28, 149, 144, 224, 28, 223, 35, 146, 169, 0, 0, 0, 0, 0, 0, 0, 64, 68,
                141, 148, 184, 183, 93, 124, 94, 83, 37, 210, 158, 29, 198, 205, 80, 195, 231, 51,
                105, 223, 240, 42, 129, 38, 242, 34, 135, 183, 137, 16, 97, 99, 78, 128, 164, 7,
                224, 218, 192, 165, 238, 164, 235, 194, 174, 23, 8, 65, 236, 151, 160, 239, 122,
                128, 137, 179, 207, 221, 144, 39, 35, 41, 197, 187, 16, 201, 230, 68, 12, 227, 117,
                56, 166, 196, 208, 5, 218, 2, 154,
            ]),
            ..Default::default()
        },
    }
}

pub(super) fn eddsa_key_for_did_mdl() -> TestKey {
    TestKey {
        multibase: "".to_string(),
        params: eddsa_testing_params(),
    }
}

pub(super) fn es256_key_for_did_mdl() -> TestKey {
    TestKey {
        multibase: "".to_string(),
        params: es256_testing_params(),
    }
}

pub(super) fn eddsa_key_2() -> TestKey {
    TestKey {
        multibase: "z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5".to_string(),
        params: TestingKeyParams {
            key_type: Some("EDDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                53, 41, 236, 251, 185, 9, 201, 18, 100, 252, 20, 153, 131, 142, 218, 73, 109, 237,
                68, 35, 207, 20, 15, 39, 108, 188, 153, 46, 114, 75, 86, 224,
            ]),
            key_reference: Some(vec![
                103, 220, 116, 52, 196, 76, 31, 218, 7, 98, 15, 113, 0, 0, 0, 0, 0, 0, 0, 64, 24,
                146, 78, 36, 166, 76, 92, 244, 62, 141, 72, 168, 119, 97, 65, 237, 225, 64, 143,
                194, 12, 54, 139, 194, 174, 4, 166, 254, 120, 85, 50, 195, 244, 114, 34, 66, 225,
                119, 93, 162, 209, 171, 21, 33, 239, 46, 38, 225, 251, 115, 125, 119, 103, 172, 90,
                0, 57, 203, 39, 186, 177, 154, 133, 61, 38, 126, 230, 178, 135, 149, 20, 28, 80,
                208, 0, 205, 166, 10, 225, 50,
            ]),
            ..Default::default()
        },
    }
}

pub(super) fn ecdsa_key_1() -> TestKey {
    TestKey {
        multibase: "zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6".to_string(),
        params: TestingKeyParams {
            key_type: Some("ES256".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 41, 83, 61, 165, 86, 37, 125, 46, 237, 61, 7, 255, 169, 76, 11, 51, 20, 151,
                189, 221, 246, 169, 103, 136, 2, 114, 144, 254, 4, 26, 202, 33,
            ]),
            key_reference: Some(vec![
                214, 40, 173, 242, 210, 229, 35, 49, 245, 164, 136, 170, 0, 0, 0, 0, 0, 0, 0, 32,
                168, 61, 62, 181, 162, 142, 116, 226, 190, 20, 146, 183, 17, 166, 110, 17, 207, 54,
                243, 166, 143, 172, 23, 72, 196, 139, 42, 147, 222, 122, 234, 133, 236, 18, 64,
                113, 85, 218, 233, 136, 236, 48, 86, 184, 249, 54, 210, 76,
            ]),
            ..Default::default()
        },
    }
}

pub(super) fn ecdsa_key_2() -> TestKey {
    TestKey {
        multibase: "zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ".to_string(),
        params: TestingKeyParams {
            key_type: Some("ES256".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 113, 223, 203, 78, 208, 144, 157, 171, 118, 94, 112, 196, 150, 233, 175, 129, 0,
                12, 229, 151, 39, 80, 197, 83, 144, 248, 160, 227, 159, 2, 215, 39,
            ]),
            key_reference: Some(vec![
                191, 117, 227, 19, 61, 61, 70, 152, 133, 158, 83, 244, 0, 0, 0, 0, 0, 0, 0, 32, 1,
                0, 223, 243, 57, 200, 101, 206, 133, 43, 169, 194, 153, 38, 105, 35, 100, 79, 106,
                61, 68, 62, 9, 96, 48, 202, 28, 74, 43, 89, 96, 100, 154, 148, 140, 180, 17, 135,
                78, 216, 169, 229, 27, 196, 181, 163, 95, 116,
            ]),
            ..Default::default()
        },
    }
}
pub(super) fn bbs_key_1() -> TestKey {
    TestKey {
        multibase: "zUC77bqRWgmZNzUQHeSSuQTiMc2Pqv3uTp1oWgbwrXushHz4Y5CbCG3WRZVo93qMwqKqizMbA6ntv\
            gGBXq5ZoHZ6HseTN842bp43GkR3N1Sw7TkJ52uQPUEyWYVD5ggtnn1E85W"
            .to_string(),
        params: TestingKeyParams {
            key_type: Some("BBS_PLUS".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                147, 93, 112, 129, 203, 111, 44, 119, 169, 7, 95, 132, 153, 185, 198, 198, 129, 84,
                156, 55, 184, 61, 204, 119, 111, 122, 160, 163, 48, 239, 33, 137, 125, 140, 163,
                102, 57, 192, 136, 126, 86, 183, 128, 140, 219, 199, 154, 22, 15, 128, 57, 87, 78,
                30, 140, 204, 70, 118, 7, 231, 236, 124, 182, 174, 78, 221, 147, 133, 22, 141, 5,
                68, 223, 121, 15, 120, 12, 199, 148, 247, 139, 220, 251, 131, 254, 247, 142, 138,
                222, 72, 105, 81, 218, 112, 27, 233,
            ]),
            key_reference: Some(vec![
                106, 24, 25, 239, 49, 159, 115, 152, 71, 187, 10, 249, 0, 0, 0, 0, 0, 0, 0, 32, 78,
                70, 91, 108, 197, 78, 54, 13, 243, 59, 43, 81, 46, 122, 63, 210, 19, 49, 124, 233,
                140, 70, 195, 60, 62, 175, 172, 120, 48, 121, 166, 240, 209, 195, 125, 120, 45,
                199, 92, 119, 53, 237, 185, 129, 6, 109, 32, 97,
            ]),
            ..Default::default()
        },
    }
}

pub(super) fn get_simple_context(
    schema_id: &CredentialSchemaId,
    schema_name_pascal: &str,
    base_url: &str,
) -> (String, String) {
    let url = format!("{base_url}/ssi/context/v1/{schema_id}");
    let context = json!(
        {
            "@context": {
                "@version": 1.1,
                "@protected": true,
                "id": "@id",
                "type": "@type",
                format!("{schema_name_pascal}Credential"): {
                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#{schema_name_pascal}Credential"),
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type"
                    }
                },
                format!("{schema_name_pascal}Subject"): {
                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#{schema_name_pascal}Subject"),
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "Key": format!("{base_url}/ssi/context/v1/{schema_id}#Key"),
                        "Name": format!("{base_url}/ssi/context/v1/{schema_id}#Name"),
                        "Address": format!("{base_url}/ssi/context/v1/{schema_id}#Address")
                    }
                }
            }
        }
    )
    .to_string();
    (url, context)
}

pub(super) fn get_simple_context_bbsplus(
    schema_id: &CredentialSchemaId,
    schema_name_pascal: &str,
    base_url: &str,
) -> (String, String) {
    let url = format!("{base_url}/ssi/context/v1/{schema_id}");
    let context = json!(
        {
            "@context": {
                "@version": 1.1,
                "@protected": true,
                "id": "@id",
                "type": "@type",
                format!("{schema_name_pascal}Credential"): {
                    "@id": format!("{}/ssi/context/v1/{schema_id}#{schema_name_pascal}Credential", base_url),
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type"
                    }
                },
                format!("{schema_name_pascal}Subject"): {
                    "@id": format!("{}/ssi/context/v1/{schema_id}#{schema_name_pascal}Subject", base_url),
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "Key 1": format!("{}/ssi/context/v1/{schema_id}#Key%201", base_url),
                        "USCIS#": format!("{}/ssi/context/v1/{schema_id}#USCIS%23", base_url),
                        "Address root": {
                            "@context": {
                                "Address1": format!("{}/ssi/context/v1/{schema_id}#Address1", base_url),
                                "Address2": format!("{}/ssi/context/v1/{schema_id}#Address2", base_url),
                            },
                            "@id": format!("{}/ssi/context/v1/{schema_id}#Address%20root", base_url),
                        },
                    }
                }
            }
        }
    ).to_string();
    (url, context)
}

pub(super) fn get_array_context(
    schema_id: &CredentialSchemaId,
    schema_name_pascal: &str,
    base_url: &str,
) -> (String, String) {
    let url = format!("{base_url}/ssi/context/v1/{schema_id}");
    let context = json!(
        {
            "@context": {
                "@version": 1.1,
                "@protected": true,
                "id": "@id",
                "type": "@type",
                format!("{schema_name_pascal}Credential"): {
                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#{schema_name_pascal}Credential"),
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type"
                    }
                },
                format!("{schema_name_pascal}Subject"): {
                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#{schema_name_pascal}Subject"),
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "root": {
                            "@context": {
                                "array": {
                                    //"@container": "@list",
                                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#array"),
                                },
                                "object_array": {
                                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#object_array"),
                                    "@context": {
                                        "field1": format!("{base_url}/ssi/context/v1/{schema_id}#field1"),
                                        "field2": format!("{base_url}/ssi/context/v1/{schema_id}#field2"),
                                    }
                                },
                            },
                            "@id": format!("{base_url}/ssi/context/v1/{schema_id}#root"),
                        },
                    }
                }
            }
        }
    ).to_string();
    (url, context)
}
