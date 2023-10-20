use super::KeyService;

use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::data_structure::CoreConfig,
    model::{
        key::{GetKeyList, Key},
        organisation::Organisation,
    },
    provider::key_storage::{
        mock_key_storage::MockKeyStorage, provider::KeyProviderImpl, GeneratedKey, KeyStorage,
    },
    repository::mock::{
        key_repository::MockKeyRepository, organisation_repository::MockOrganisationRepository,
    },
    service::{
        key::dto::{GetKeyQueryDTO, KeyRequestDTO},
        test_utilities::generic_config,
    },
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

fn generic_key(name: &str, organisation_id: Uuid) -> Key {
    let now = OffsetDateTime::now_utc();
    Key {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        public_key: vec![],
        name: name.to_owned(),
        private_key: vec![],
        storage_type: "MOCK".to_string(),
        key_type: "RSA4096".to_string(),
        organisation: Some(Organisation {
            id: organisation_id,
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

    let org_id = Uuid::new_v4();

    let key = generic_key("NAME", org_id);
    let organisation = key.organisation.to_owned().unwrap();
    {
        let organisation = organisation.clone();

        organisation_repository
            .expect_get_organisation()
            .times(1)
            .returning(move |_, _| Ok(organisation.clone()));

        key_storage.expect_generate().times(1).returning(move |_| {
            Ok(GeneratedKey {
                public: vec![],
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

    assert!(result.is_ok());
    assert_eq!(key.id, result.unwrap());
}

#[tokio::test]
async fn test_get_key_success() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();

    let org_id: Uuid = Uuid::new_v4();
    let key = generic_key("NAME", org_id);
    {
        let key = key.clone();
        repository
            .expect_get_key()
            .times(1)
            .returning(move |_, _| Ok(key.clone()));
    }

    let service = setup_service(
        repository,
        organisation_repository,
        key_storage,
        generic_config(),
    );

    let result = service.get_key(&key.id).await;

    assert!(result.is_ok());
    assert_eq!(key.id, result.unwrap().id);
}

#[tokio::test]
async fn test_get_key_list() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();
    let org_id: Uuid = Uuid::new_v4();
    let keys = vec![generic_key("NAME1", org_id), generic_key("NAME2", org_id)];

    let moved_keys = keys.clone();
    repository
        .expect_get_key_list()
        .times(1)
        .returning(move |_| {
            Ok(GetKeyList {
                values: moved_keys.clone(),
                total_pages: 1,
                total_items: 2,
            })
        });

    let service = setup_service(
        repository,
        organisation_repository,
        key_storage,
        generic_config(),
    );

    let query = GetKeyQueryDTO {
        page: 0,
        page_size: 10,
        sort: None,
        sort_direction: None,
        name: Some("NAME".to_owned()),
        organisation_id: org_id.to_string(),
        exact: None,
    };

    let result = service.get_key_list(query).await;

    assert!(result.is_ok());

    let data = result.unwrap();

    assert_eq!(data.total_items, 2);
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.values.len(), 2);

    assert_eq!(data.values[0].name, keys[0].name);
    assert_eq!(data.values[1].name, keys[1].name);
}
