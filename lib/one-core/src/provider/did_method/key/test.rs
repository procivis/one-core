use crate::config::core_config::{Fields, KeyAlgorithmConfig, KeyAlgorithmType, Params};
use crate::crypto::MockCryptoProvider;
use crate::model::key::Key;
use crate::provider::did_method::dto::{
    DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::did_method::{provider::DidMethodProviderImpl, DidMethod};
use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use serde_json::json;
use shared_types::{DidId, DidValue};
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{DidKeyParams, KeyDidMethod};

fn setup_provider(key_algorithm: MockKeyAlgorithm) -> Arc<dyn DidMethodProvider + Send + Sync> {
    let mut key_algorithms: HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>> = HashMap::new();
    key_algorithms.insert("EDDSA".to_string(), Arc::new(key_algorithm));

    let key_algorithm_provider =
        KeyAlgorithmProviderImpl::new(key_algorithms, Arc::new(MockCryptoProvider::new()));

    let mut key_algorithm_config = KeyAlgorithmConfig::default();
    key_algorithm_config.insert(
        KeyAlgorithmType::Eddsa,
        Fields {
            r#type: "EDDSA".to_string(),
            display: "EDDSA".to_string(),
            order: None,
            disabled: None,
            params: Some(Params {
                public: Some(json!({
                    "algorithm": "Ed25519"
                })),
                private: None,
            }),
        },
    );

    let mut did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>> = HashMap::new();
    did_methods.insert(
        "KEY".to_string(),
        Arc::new(KeyDidMethod::new(
            Arc::new(key_algorithm_provider),
            key_algorithm_config,
            DidKeyParams,
            "KEY".to_string(),
        )),
    );

    Arc::new(DidMethodProviderImpl::new(did_methods))
}

// test vectors taken from:
// - https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/ed25519-x25519.json
// - https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/nist-curves.json
const TEST_VECTORS: [&str; 4] = [
    ("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"),
    ("did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"),
    ("did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"),
    ("did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb"),
];

#[tokio::test]
async fn test_did_key_resolve_wide() {
    let provider = setup_provider(MockKeyAlgorithm::default());

    for did in TEST_VECTORS {
        let result = provider.resolve(&did.parse().unwrap()).await.unwrap();
        assert!(!result.verification_method.is_empty());
        assert!(!result.assertion_method.unwrap().is_empty());
    }
}

#[tokio::test]
async fn test_did_key_resolve_details() {
    let provider = setup_provider(MockKeyAlgorithm::default());
    let result = provider
        .resolve(
            &"did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb"
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(result,
    DidDocumentDTO {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
        ],
        id: DidValue::from_str("did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb").unwrap(),
        verification_method: vec![
            DidVerificationMethodDTO {
                id: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
                r#type: "JsonWebKey2020".to_owned(),
                controller: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
                public_key_jwk: PublicKeyJwkDTO::Ec(
                    PublicKeyJwkEllipticDataDTO {
                        crv: "P-256".to_owned(),
                        x: "AjDk2GBBiI_M6HvEmgfzXiVhJCWiVFqvoItknJgc-oEE".to_owned(),
                        y: None,
                    },
                ),
            },
        ],
        authentication: Some(
            vec![
                "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
            ],
        ),
        assertion_method: Some(
            vec![
                "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
            ],
        ),
        key_agreement: Some(
            vec![
                "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
            ],
        ),
        capability_invocation: Some(
            vec![
                "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
            ],
        ),
        capability_delegation: Some(
            vec![
                "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
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

    let provider = setup_provider(key_algorithm);
    let did_method = provider.get_did_method("KEY").unwrap();
    let result = did_method
        .create(&DidId::from(Uuid::new_v4()), &None, &Some(key))
        .await;
    result.unwrap();
}
