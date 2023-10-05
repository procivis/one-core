use super::KeyService;

use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::data_structure::CoreConfig,
    key_storage::{
        mock_key_storage::MockKeyStorage, provider::KeyProviderImpl, GeneratedKey, KeyStorage,
    },
    model::{key::Key, organisation::Organisation},
    repository::mock::{
        key_repository::MockKeyRepository, organisation_repository::MockOrganisationRepository,
    },
    service::{key::dto::KeyRequestDTO, test_utilities::generic_config},
};

fn setup_service(
    repository: MockKeyRepository,
    organisation_repository: MockOrganisationRepository,
    key_storage: MockKeyStorage,
    config: CoreConfig,
) -> KeyService {
    let mut storages: HashMap<String, Arc<dyn KeyStorage + Send + Sync>> = HashMap::new();
    storages.insert("MOCK".to_string(), Arc::new(key_storage));

    let provider = KeyProviderImpl::new(storages);

    KeyService::new(
        Arc::new(repository),
        Arc::new(organisation_repository),
        Arc::new(provider),
        Arc::new(config),
    )
}

fn generic_key() -> Key {
    let now = OffsetDateTime::now_utc();
    Key {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        public_key: "".to_string(),
        name: "NAME".to_string(),
        private_key: vec![],
        storage_type: "MOCK".to_string(),
        key_type: "RSA4096".to_string(),
        credential: None,
        dids: None,
        organisation: Some(Organisation {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
        }),
    }
}

#[tokio::test]
async fn test_create_key_success() {
    let mut repository = MockKeyRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut key_storage = MockKeyStorage::default();

    let key = generic_key();
    let organisation = key.organisation.to_owned().unwrap();
    {
        let organisation = organisation.clone();

        organisation_repository
            .expect_get_organisation()
            .times(1)
            .returning(move |_, _| Ok(organisation.clone()));

        key_storage.expect_generate().times(1).returning(move |_| {
            Ok(GeneratedKey {
                public: "".to_string(),
                private: vec![],
            })
        });

        repository
            .expect_create_key()
            .times(1)
            .returning(move |_| Ok(key.id));
    }

    let service = setup_service(
        repository,
        organisation_repository,
        key_storage,
        generic_config(),
    );

    let result = service
        .generate_key(KeyRequestDTO {
            organisation_id: organisation.id,
            key_type: "EDDSA".to_string(),
            key_params: Default::default(),
            name: "NAME".to_string(),
            storage_type: "MOCK".to_string(),
            storage_params: Default::default(),
        })
        .await;

    result.unwrap();
    /*assert!(result.is_ok());
    assert_eq!(key.id, result.unwrap());*/
}
