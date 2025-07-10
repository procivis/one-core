use core::panic;
use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hex_literal::hex;
use one_core::config::core_config::KeyAlgorithmType;
use one_core::model::key::{Key, PublicKeyJwk};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_storage::KeyStorage;
use one_core::provider::key_storage::internal::{InternalKeyProvider, Params};
use one_core::service::key::dto::PublicKeyJwkDTO;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::TestingKeyParams;

#[derive(Clone)]
pub struct TestKey {
    multibase: String,
    pub params: TestingKeyParams,
    jwk: PublicKeyJwk,
}

pub fn eddsa_key_2() -> TestKey {
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

pub(super) async fn proof_jwt(use_kid: bool, nonce: Option<&str>) -> String {
    let holder_key = eddsa_key_2();
    let holder_key_id = format!("did:key:{}", holder_key.multibase);
    proof_jwt_for(&holder_key, use_kid.then_some(&holder_key_id), nonce).await
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
        key_reference: params.key_reference,
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
