use std::collections::HashMap;
use std::sync::Arc;

use mockall::predicate;
use secrecy::SecretSlice;
use serde_json::json;
use shared_types::DidId;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::KeyDidMethod;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::did_method::model::{AmountOfKeys, DidDocument, DidVerificationMethod};
use crate::provider::did_method::{DidKeys, DidMethod};
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};

fn setup_key_did_method(
    key_algorithm: MockKeyAlgorithm,
    algorithm_id: KeyAlgorithmType,
) -> KeyDidMethod {
    let mut key_algorithms: HashMap<KeyAlgorithmType, Arc<dyn KeyAlgorithm>> = HashMap::new();
    key_algorithms.insert(algorithm_id, Arc::new(key_algorithm));

    let key_algorithm_provider = KeyAlgorithmProviderImpl::new(key_algorithms);

    KeyDidMethod::new(Arc::new(key_algorithm_provider))
}

#[tokio::test]
async fn test_did_key_resolve_details_eddsa() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_reconstruct_key()
        .with(
            predicate::eq(vec![
                59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50,
                21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
            ]),
            predicate::function(|val: &Option<SecretSlice<u8>>| val.is_none()),
            predicate::always(),
        )
        .return_once(|_, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                    r#use: None,
                    kid: None,
                    crv: "Ed25519".to_owned(),
                    x: "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS".to_owned(),
                    y: None,
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let did_method = setup_key_did_method(key_algorithm, KeyAlgorithmType::Eddsa);

    let result = did_method
        .resolve(
            &"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(result,
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".parse().unwrap(),
        verification_method: vec![
            DidVerificationMethod {
                id: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
                public_key_jwk: PublicKeyJwk::Okp(
                    PublicKeyJwkEllipticData {
                        r#use: None,
                        kid: None,
                        crv: "Ed25519".to_owned(),
                        x: "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS".to_owned(),
                        y: None,
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
            ],
        ),
        also_known_as: None,
        service: None,
    });
}

// https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
#[tokio::test]
async fn test_did_key_resolve_details_ecdsa() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_reconstruct_key()
        .with(
            predicate::eq(vec![
                3, 138, 10, 197, 154, 45, 48, 134, 232, 161, 42, 120, 253, 71, 115, 166, 213, 42,
                12, 166, 30, 246, 193, 65, 158, 21, 160, 91, 204, 109, 175, 206, 123,
            ]),
            predicate::function(|val: &Option<SecretSlice<u8>>| val.is_none()),
            predicate::always(),
        )
        .return_once(|_, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let did_method = setup_key_did_method(key_algorithm, KeyAlgorithmType::Ecdsa);

    let result = did_method
        .resolve(
            &"did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(result,
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".parse().unwrap(),
        verification_method: vec![
            DidVerificationMethod {
                id: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
                public_key_jwk: PublicKeyJwk::Ec(
                    PublicKeyJwkEllipticData {
                        r#use: None,
                        kid: None,
                        crv: "P-256".to_owned(),
                        x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                        y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
            ],
        ),
        also_known_as: None,
        service: None,
    });
}

#[tokio::test]
async fn test_did_key_resolve_details_bbs() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_reconstruct_key()
        .with(
            predicate::eq(vec![
                130, 59, 60, 150, 203, 83, 130, 132, 224, 92, 193, 122, 65, 119, 114, 135, 121,
                188, 147, 104, 177, 197, 68, 70, 96, 179, 26, 99, 41, 85, 43, 252, 116, 23, 193,
                225, 19, 204, 228, 209, 133, 162, 25, 93, 194, 31, 10, 80, 17, 173, 172, 31, 131,
                193, 100, 182, 152, 10, 127, 44, 123, 237, 92, 150, 96, 142, 68, 59, 10, 197, 182,
                240, 220, 155, 63, 2, 91, 184, 58, 105, 21, 246, 9, 155, 38, 204, 181, 96, 93, 171,
                183, 181, 113, 206, 206, 146,
            ]),
            predicate::function(|val: &Option<SecretSlice<u8>>| val.is_none()),
            predicate::always(),
        )
        .return_once(|_, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle
                .expect_as_jwk()
                .return_once(||  Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                r#use: None,
                kid: None,
                crv: "Bls12381G2".to_string(),
                x: "Ajs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S".to_owned(),
                y: Some("BVkkrVEib-P_FMPHNtqxJymP3pV-H8fCdvPkoWInpFfM9tViyqD8JAmwDf64zU2hBV_vvCQ632ScAooEExXuz1IeQH9D2o-uY_dAjZ37YHuRMEyzh8Tq-90JHQvicOqx".to_owned()),
            })));

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let did_method = setup_key_did_method(key_algorithm, KeyAlgorithmType::BbsPlus);

    let result = did_method
        .resolve(
            &"did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(result,
    DidDocument {
        context: json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ]),
        id: "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".parse().unwrap(),
        verification_method: vec![
            DidVerificationMethod {
                id: "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
                public_key_jwk: PublicKeyJwk::Okp(
                    PublicKeyJwkEllipticData {
                        r#use: None,
                        kid: None,
                        crv: "Bls12381G2".to_string(),
                        x: "Ajs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S".to_owned(),
                        y: Some("BVkkrVEib-P_FMPHNtqxJymP3pV-H8fCdvPkoWInpFfM9tViyqD8JAmwDf64zU2hBV_vvCQ632ScAooEExXuz1IeQH9D2o-uY_dAjZ37YHuRMEyzh8Tq-90JHQvicOqx".to_owned()),
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:key:zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo#zUC71hWmiaLNZL97NxPkesvV6jV5UuxT2UUMo9fMGfsh5nV5NLU2HVFdX2DcDn8dQDKvur2U1tMjy34nnjEFF3dfdJgYRCBi5Sxup75PNNZrtJTrqrM23m9tUZ7KX9TM9dT38mo".to_owned(),
            ],
        ),
        also_known_as: None,
        service: None,
    });
}

#[tokio::test]
async fn test_create_did_success() {
    let key_id = Uuid::new_v4();

    let key = Key {
        id: key_id.into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "".to_string(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_reconstruct_key()
        .return_once(|_, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle
                .expect_as_multibase()
                .return_once(|| Ok("MULTIBASE".to_string()));

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let did_method = setup_key_did_method(key_algorithm, KeyAlgorithmType::Eddsa);
    let keys = vec![key];
    let result = did_method
        .create(
            Some(DidId::from(Uuid::new_v4())),
            &None,
            Some(DidKeys {
                authentication: keys.clone(),
                assertion_method: keys.clone(),
                key_agreement: keys.clone(),
                capability_invocation: keys.clone(),
                capability_delegation: keys.clone(),
                update_keys: None,
            }),
        )
        .await;
    result.unwrap();
}

#[test]
fn test_validate_keys() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), KeyAlgorithmType::Eddsa);

    let keys = AmountOfKeys {
        global: 1,
        authentication: 1,
        assertion_method: 1,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_no_keys() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), KeyAlgorithmType::Eddsa);

    let keys = AmountOfKeys {
        global: 0,
        authentication: 0,
        assertion_method: 0,
        key_agreement: 0,
        capability_invocation: 0,
        capability_delegation: 0,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_too_much_keys() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), KeyAlgorithmType::Eddsa);

    let keys = AmountOfKeys {
        global: 2,
        authentication: 1,
        assertion_method: 1,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(!did_method.validate_keys(keys));
}

#[test]
fn test_validate_keys_missing_key() {
    let did_method = setup_key_did_method(MockKeyAlgorithm::default(), KeyAlgorithmType::Eddsa);

    let keys = AmountOfKeys {
        global: 1,
        authentication: 1,
        assertion_method: 0,
        key_agreement: 1,
        capability_invocation: 1,
        capability_delegation: 1,
    };
    assert!(!did_method.validate_keys(keys));
}
