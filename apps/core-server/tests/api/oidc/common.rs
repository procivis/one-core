use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hex_literal::hex;
use one_core::model::key::Key;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::key::KeyHandle;
use one_core::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
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
}

pub fn eddsa_key_2() -> TestKey {
    let multibase = "z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5".to_string();
    TestKey {
        multibase,
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
    let holder_key_id = format!("did:key:{}#{}", holder_key.multibase, holder_key.multibase);

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| Some(Arc::new(Eddsa)));

    let params = holder_key.params.clone();
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

    let encryption_key = hex!("93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e");
    let key_provider = InternalKeyProvider::new(
        Arc::new(key_algorithm_provider),
        Params {
            encryption: encryption_key.to_vec().into(),
        },
    );
    let key_handle = key_provider.key_handle(&key).unwrap();

    proof_jwt_for(
        &key_handle,
        "EdDSA".to_string(),
        use_kid.then_some(&holder_key_id),
        nonce,
    )
    .await
}

pub async fn proof_jwt_for(
    key: &KeyHandle,
    jose_alg: String,
    holder_key_id: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let mut header = json!({
        "typ": "openid4vci-proof+jwt"
    });
    if let Some(holder_key_id) = holder_key_id {
        header["kid"] = holder_key_id.into();
    } else {
        header["jwk"] =
            serde_json::to_value(PublicKeyJwkDTO::from(key.public_key_as_jwk().unwrap())).unwrap();
    }

    let mut payload = json!({
        "aud": "test123"
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = nonce.into();
    }

    header["alg"] = jose_alg.into();

    let jwt = [header.to_string(), payload.to_string()]
        .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
        .join(".");

    let signature = key.sign(jwt.as_bytes()).await.unwrap();
    let signature = Base64UrlSafeNoPadding::encode_to_string(&signature).unwrap();

    [jwt, signature].join(".")
}
