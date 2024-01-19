use crate::config::core_config::{Fields, KeyAlgorithmConfig, KeyAlgorithmType};
use crate::crypto::MockCryptoProvider;
use crate::model::key::Key;
use crate::provider::did_method::dto::{
    DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::did_method::{provider::DidMethodProviderImpl, DidMethod};
use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use mockall::predicate;
use serde_json::Value;
use shared_types::{DidId, DidValue};
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

use super::KeyDidMethod;

fn setup_provider(
    key_algorithm: MockKeyAlgorithm,
    algorithm_id: &str,
    algorithm_type: KeyAlgorithmType,
) -> Arc<dyn DidMethodProvider> {
    let mut key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm>> = HashMap::new();
    key_algorithms.insert(algorithm_id.to_string(), Arc::new(key_algorithm));

    let key_algorithm_provider =
        KeyAlgorithmProviderImpl::new(key_algorithms, Arc::new(MockCryptoProvider::new()));

    let mut key_algorithm_config = KeyAlgorithmConfig::default();
    key_algorithm_config.insert(
        algorithm_type,
        Fields {
            r#type: algorithm_id.to_string(),
            display: Value::String(algorithm_id.to_string()),
            order: None,
            disabled: None,
            capabilities: None,
            params: None,
        },
    );

    let mut did_methods: HashMap<String, Arc<dyn DidMethod>> = HashMap::new();
    did_methods.insert(
        "KEY".to_string(),
        Arc::new(KeyDidMethod::new(Arc::new(key_algorithm_provider))),
    );

    Arc::new(DidMethodProviderImpl::new(did_methods))
}

#[tokio::test]
async fn test_did_key_resolve_details_eddsa() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_bytes_to_jwk()
        .with(predicate::eq(vec![
            59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21,
            119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
        ]))
        .once()
        .returning(|_| {
            Ok(PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
                r#use: None,
                crv: "Ed25519".to_owned(),
                x: "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS".to_owned(),
                y: None,
            }))
        });

    let provider = setup_provider(key_algorithm, "EDDSA", KeyAlgorithmType::Eddsa);

    let result = provider
        .resolve(
            &"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(result,
    DidDocumentDTO {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/suites/jws-2020/v1".into(),
        ],
        id: DidValue::from_str("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp").unwrap(),
        verification_method: vec![
            DidVerificationMethodDTO {
                id: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".to_owned(),
                public_key_jwk: PublicKeyJwkDTO::Okp(
                    PublicKeyJwkEllipticDataDTO {
                        r#use: None,
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
    });
}

// https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
#[tokio::test]
async fn test_did_key_resolve_details_es256() {
    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_bytes_to_jwk()
        .with(predicate::eq(vec![
            3, 138, 10, 197, 154, 45, 48, 134, 232, 161, 42, 120, 253, 71, 115, 166, 213, 42, 12,
            166, 30, 246, 193, 65, 158, 21, 160, 91, 204, 109, 175, 206, 123,
        ]))
        .once()
        .returning(|_| {
            Ok(PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
                r#use: None,
                crv: "P-256".to_string(),
                x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
            }))
        });

    let provider = setup_provider(key_algorithm, "ES256", KeyAlgorithmType::Es256);

    let result = provider
        .resolve(
            &"did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(result,
    DidDocumentDTO {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/suites/jws-2020/v1".into(),
        ],
        id: DidValue::from_str("did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv").unwrap(),
        verification_method: vec![
            DidVerificationMethodDTO {
                id: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv".to_owned(),
                public_key_jwk: PublicKeyJwkDTO::Ec(
                    PublicKeyJwkEllipticDataDTO {
                        r#use: None,
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
    });
}

#[tokio::test]
async fn test_create_did_success() {
    let key_id = Uuid::new_v4();

    let key = Key {
        id: key_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "".to_string(),
        key_reference: vec![],
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_get_multibase()
        .times(1)
        .returning(|_| "MULTIBASE".to_string());

    let provider = setup_provider(key_algorithm, "EDDSA", KeyAlgorithmType::Eddsa);
    let did_method = provider.get_did_method("KEY").unwrap();
    let result = did_method
        .create(&DidId::from(Uuid::new_v4()), &None, &Some(key))
        .await;
    result.unwrap();
}
