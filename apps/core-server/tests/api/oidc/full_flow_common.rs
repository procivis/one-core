use core::panic;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hex_literal::hex;
use one_core::config::core_config::KeyAlgorithmType;
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::key::{Key, PublicKeyJwk};
use one_core::model::organisation::Organisation;
use one_core::provider::key_algorithm::bbs::BBS;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_storage::internal::{InternalKeyProvider, Params};
use one_core::provider::key_storage::KeyStorage;
use one_core::service::key::dto::PublicKeyJwkDTO;
use serde_json::json;
use shared_types::{CredentialSchemaId, DidValue};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{TestingDidParams, TestingKeyParams};
use crate::utils::context::TestContext;

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
    jwk: PublicKeyJwk,
}

pub(super) fn eddsa_key_1() -> TestKey {
    let multibase = "z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB".to_string();
    let jwk = Eddsa
        .parse_multibase(&multibase)
        .unwrap()
        .public_key_as_jwk()
        .unwrap();
    TestKey {
        multibase,
        jwk,
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

pub(super) fn eddsa_key_2() -> TestKey {
    let multibase = "z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5".to_string();
    let jwk = Eddsa
        .parse_multibase(&multibase)
        .unwrap()
        .public_key_as_jwk()
        .unwrap();
    TestKey {
        multibase,
        jwk,
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

pub(super) fn bbs_key_1() -> TestKey {
    let multibase = "zUC77bqRWgmZNzUQHeSSuQTiMc2Pqv3uTp1oWgbwrXushHz4Y5CbCG3WRZVo93qMwqKqizMbA6ntv\
            gGBXq5ZoHZ6HseTN842bp43GkR3N1Sw7TkJ52uQPUEyWYVD5ggtnn1E85W"
        .to_string();
    let jwk = BBS
        .parse_multibase(&multibase)
        .unwrap()
        .public_key_as_jwk()
        .unwrap();
    TestKey {
        multibase,
        jwk,
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
                "ProcivisOneSchema2024": {
                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#ProcivisOneSchema2024"),
                    "@context": {
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "metadata": {
                            "@id": format!("{base_url}/ssi/context/v1/{schema_id}#metadata"),
                            "@type": "@json"
                        }
                    }
                },
                schema_name_pascal: {
                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#{schema_name_pascal}", ),
                },
                "TestSubject": {
                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#TestSubject"),
                    "@context": {
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        "Key 1": {
                            "@id": format!("{base_url}/ssi/context/v1/{schema_id}#Key%201"),
                        },
                        "USCIS#": {
                            "@id": format!("{base_url}/ssi/context/v1/{schema_id}#USCIS%23"),
                        },
                        "Address root": {
                            "@id": format!("{base_url}/ssi/context/v1/{schema_id}#Address%20root"),
                            "@context": {
                                "@protected": true,
                                "id": "@id",
                                "type": "@type",
                                "Address1": {
                                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#Address1"),
                                },
                                "Address2": {
                                    "@id": format!("{base_url}/ssi/context/v1/{schema_id}#Address2"),
                                },
                            },
                        },
                    }
                }
            }
        }
    ).to_string();

    (url, context)
}

pub(super) async fn proof_jwt(use_kid: bool, nonce: Option<&str>) -> (String, String) {
    let holder_key = eddsa_key_2();
    let holder_key_id = format!("did:key:{}", holder_key.multibase);
    (
        proof_jwt_for(&holder_key, use_kid.then_some(&holder_key_id), nonce).await,
        holder_key_id,
    )
}

pub(super) async fn proof_jwt_for(
    key: &TestKey,
    holder_key_id: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let mut header = json!({
        "typ": "openid4vci-proof+jwt"
    });
    if let Some(holder_key_id) = holder_key_id {
        header["kid"] = holder_key_id.into();
    } else {
        header["jwk"] = serde_json::to_value(PublicKeyJwkDTO::from(key.jwk.clone())).unwrap();
    }

    let mut payload = json!({
        "aud": "test123"
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = nonce.into();
    }

    match key.params.key_type.as_deref() {
        Some("EDDSA") => {
            header["alg"] = "EdDSA".into();
        }
        Some("ECDSA") => {
            header["alg"] = "ES256".into();
        }
        kty => {
            panic!("Unsupported key type: {kty:?}");
        }
    };

    let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter([
        (
            KeyAlgorithmType::Eddsa,
            Arc::new(Eddsa) as Arc<dyn KeyAlgorithm>,
        ),
        (
            KeyAlgorithmType::Ecdsa,
            Arc::new(Ecdsa) as Arc<dyn KeyAlgorithm>,
        ),
    ])));
    let encryption_key = hex!("93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e");
    let key_provider = InternalKeyProvider::new(
        key_algorithm_provider,
        Params {
            encryption: encryption_key.to_vec().into(),
        },
    );

    let params = key.params.clone();
    let key = Key {
        id: params.id.unwrap_or(Uuid::new_v4().into()),
        created_date: params.created_date.unwrap_or(OffsetDateTime::now_utc()),
        last_modified: params.last_modified.unwrap_or(OffsetDateTime::now_utc()),
        public_key: params.public_key.unwrap_or_default(),
        name: "test-key".to_string(),
        key_reference: params.key_reference.unwrap_or_default(),
        storage_type: params.storage_type.unwrap_or_default(),
        key_type: params.key_type.unwrap_or_default(),
        organisation: None,
    };

    let jwt = [header.to_string(), payload.to_string()]
        .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
        .join(".");

    let key_handle = key_provider.key_handle(&key).unwrap();

    let signature = key_handle.sign(jwt.as_bytes()).await.unwrap();
    let signature = Base64UrlSafeNoPadding::encode_to_string(&signature).unwrap();

    [jwt, signature].join(".")
}
