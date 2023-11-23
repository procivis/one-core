use crate::config::core_config::{Fields, KeyAlgorithmConfig, KeyAlgorithmType, Params};
use crate::crypto::MockCryptoProvider;
use crate::model::did::{Did, DidType};
use crate::model::key::Key;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::did_method::DidMethodError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use crate::repository::mock::organisation_repository::MockOrganisationRepository;
use crate::service::did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO};
use crate::{
    model::{did::KeyRole, organisation::Organisation},
    provider::did_method::{provider::DidMethodProviderImpl, DidMethod},
    repository::did_repository::MockDidRepository,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{DidKeyParams, KeyDidMethod};

fn setup_provider(
    did_repository: MockDidRepository,
    key_algorithm: MockKeyAlgorithm,
    organisation_repository: MockOrganisationRepository,
) -> Arc<dyn DidMethodProvider + Send + Sync> {
    let did_repository = Arc::new(did_repository);

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
            did_repository,
            Arc::new(organisation_repository),
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
const TEST_VECTORS: [(&str, &str); 4] = [
    (
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS",
    ),
    (
        "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
        "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt",
    ),
    (
        "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
        "8pM1DN3RiT8vbom5u1sNryaNT1nyL8CTTW3b5PwWXRBH",
    ),
    (
        "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb",
        "ekVhkcBFq3w7jULLkBVye6PwaTuMbhJYuzwFnNcgQAPV",
    ),
];

#[tokio::test]
async fn test_did_key_resolve() {
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .returning(|did, _| {
            Ok(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "name".to_string(),
                did: did.to_owned(),
                did_type: DidType::Remote,
                did_method: "KEY".to_string(),
                keys: None,
                organisation: None,
            })
        });
    let provider = setup_provider(
        did_repository,
        MockKeyAlgorithm::default(),
        MockOrganisationRepository::default(),
    );

    for (did, public_key) in TEST_VECTORS {
        let result = provider.resolve(&did.parse().unwrap()).await.unwrap();
        let key = result
            .keys
            .unwrap()
            .into_iter()
            .find(|key| key.role == KeyRole::AssertionMethod)
            .unwrap()
            .key;
        assert_eq!(bs58::encode(key.public_key).into_string(), public_key);
    }
}

fn generic_did() -> Did {
    Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "".to_string(),
        did: "did:key:MOCK".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
        organisation: None,
    }
}

#[tokio::test]
async fn test_create_did_success() {
    let key_id = Uuid::new_v4();

    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: CreateDidRequestKeysDTO {
            authentication: vec![key_id],
            assertion: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        },
        params: None,
    };
    let key = Key {
        id: key_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "".to_string(),
        private_key: vec![],
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_get_multibase()
        .times(1)
        .returning(|_| "MULTIBASE".to_string());

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .times(1)
        .returning(|_, _| Err(crate::repository::error::DataLayerError::RecordNotFound));

    let did = generic_did();
    let did_clone = did.clone();
    did_repository
        .expect_create_did()
        .times(1)
        .returning(move |_| Ok(did_clone.id.clone()));

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| {
            Ok(Organisation {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            })
        });

    let provider = setup_provider(did_repository, key_algorithm, organisation_repository);
    let did_method = provider.get_did_method("KEY").unwrap();
    let result = did_method.create(create_request, key).await;
    result.unwrap();
}

#[tokio::test]
async fn test_create_did_already_exists() {
    let key_id = Uuid::new_v4();

    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: CreateDidRequestKeysDTO {
            authentication: vec![key_id],
            assertion: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        },
        params: None,
    };
    let key = Key {
        id: key_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "".to_string(),
        private_key: vec![],
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let mut key_algorithm = MockKeyAlgorithm::default();
    key_algorithm
        .expect_get_multibase()
        .times(1)
        .returning(|_| "MULTIBASE".to_string());

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .times(1)
        .returning(|_, _| Ok(generic_did()));

    let provider = setup_provider(
        did_repository,
        key_algorithm,
        MockOrganisationRepository::default(),
    );
    let did_method = provider.get_did_method("KEY").unwrap();
    let result = did_method.create(create_request, key).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(DidMethodError::AlreadyExists)));
}