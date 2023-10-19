use super::key::KeyDidMethod;
use super::provider::DidMethodProvider;
use crate::config::data_structure::DidKeyParams;
use crate::model::did::{Did, DidType};
use crate::provider::key_storage::provider::KeyProviderImpl;
use crate::repository::mock::organisation_repository::MockOrganisationRepository;
use crate::{
    model::{did::KeyRole, organisation::Organisation},
    provider::did_method::{provider::DidMethodProviderImpl, DidMethod},
    repository::mock::did_repository::MockDidRepository,
};
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_provider(did_repository: MockDidRepository) -> Arc<dyn DidMethodProvider + Send + Sync> {
    let did_repository = Arc::new(did_repository);

    let mut did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>> = HashMap::new();
    did_methods.insert(
        "KEY".to_string(),
        Arc::new(KeyDidMethod {
            did_repository: did_repository.clone(),
            organisation_repository: Arc::new(MockOrganisationRepository::default()),
            key_provider: Arc::new(KeyProviderImpl::new(HashMap::new())),
            method_key: "KEY".to_string(),
            params: DidKeyParams::default(),
        }),
    );

    Arc::new(DidMethodProviderImpl::new(did_methods, did_repository))
}

// test vectors taken from: https://github.com/w3c-ccg/did-method-key/blob/main/test-vectors/ed25519-x25519.json
const TEST_VECTORS: [(&str, &str); 3] = [
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
];

#[tokio::test]
async fn test_did_key_resolve() {
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .returning(|did, _| {
            Ok(Did {
                id: Uuid::new_v4(),
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
    let provider = setup_provider(did_repository);

    let organisation = Organisation {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };

    for (did, public_key) in TEST_VECTORS {
        let result = provider.resolve(did, organisation.to_owned()).await;

        assert!(result.is_ok());
        let result = result.unwrap();
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
