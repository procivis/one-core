use super::DidService;
use crate::{
    config::{
        data_structure,
        data_structure::{CoreConfig, DidEntity},
    },
    model::{
        did::{Did, DidRelations, DidType, GetDidList, KeyRole, RelatedKey},
        key::{Key, KeyRelations},
        organisation::{Organisation, OrganisationRelations},
    },
    provider::key_storage::{
        mock_key_storage::MockKeyStorage, provider::KeyProviderImpl, KeyStorage,
    },
    repository::mock::{
        did_repository::MockDidRepository, key_repository::MockKeyRepository,
        organisation_repository::MockOrganisationRepository,
    },
    service::{
        did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO, GetDidQueryDTO},
        error::ServiceError,
    },
};
use did_key::{Generate, KeyMaterial};
use mockall::predicate::*;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(
    did_repository: MockDidRepository,
    organisation_repository: MockOrganisationRepository,
    key_repository: MockKeyRepository,
    key_storage: MockKeyStorage,
    did_config: HashMap<String, DidEntity>,
) -> DidService {
    let mut storages: HashMap<String, Arc<dyn KeyStorage + Send + Sync>> = HashMap::new();
    storages.insert("MOCK".to_string(), Arc::new(key_storage));

    let key_provider = KeyProviderImpl::new(storages);

    DidService::new(
        Arc::new(did_repository),
        Arc::new(organisation_repository),
        Arc::new(key_repository),
        Arc::new(key_provider),
        Arc::new(CoreConfig {
            format: HashMap::default(),
            exchange: HashMap::default(),
            transport: HashMap::default(),
            revocation: HashMap::default(),
            did: did_config,
            datatype: HashMap::default(),
            key_algorithm: Default::default(),
            key_storage: Default::default(),
        }),
    )
}

#[tokio::test]
async fn test_get_did_exists() {
    let mut repository = MockDidRepository::default();

    let did = Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(Organisation {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                private_key: vec![],
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
        }]),
    };
    {
        let did_clone = did.clone();
        repository
            .expect_get_did()
            .times(1)
            .with(
                eq(did.id.to_owned()),
                eq(DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    keys: Some(KeyRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(did_clone.clone()));
    }

    let service = setup_service(
        repository,
        MockOrganisationRepository::default(),
        MockKeyRepository::default(),
        MockKeyStorage::default(),
        HashMap::<String, DidEntity>::new(),
    );

    let result = service.get_did(&did.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, did.id);
    assert_eq!(result.keys.authentication.len(), 1);
    assert!(result.keys.assertion.is_empty());
}

#[tokio::test]
async fn test_get_did_missing() {
    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did()
        .times(1)
        .returning(|_, _| Err(crate::repository::error::DataLayerError::RecordNotFound));

    let service = setup_service(
        repository,
        MockOrganisationRepository::default(),
        MockKeyRepository::default(),
        MockKeyStorage::default(),
        HashMap::<String, DidEntity>::new(),
    );

    let result = service.get_did(&Uuid::new_v4()).await;
    assert!(matches!(result, Err(ServiceError::NotFound)));
}

#[tokio::test]
async fn test_get_did_list() {
    let did = Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(Organisation {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
    };

    let mut repository = MockDidRepository::default();
    {
        let did_clone = did.clone();
        repository
            .expect_get_did_list()
            .times(1)
            .returning(move |_| {
                Ok(GetDidList {
                    values: vec![did_clone.clone()],
                    total_pages: 1,
                    total_items: 1,
                })
            });
    }

    let service = setup_service(
        repository,
        MockOrganisationRepository::default(),
        MockKeyRepository::default(),
        MockKeyStorage::default(),
        HashMap::<String, DidEntity>::new(),
    );

    let result = service
        .get_did_list(GetDidQueryDTO {
            page: 0,
            page_size: 1,
            sort: None,
            exact: None,
            sort_direction: None,
            name: None,
            organisation_id: Uuid::new_v4().to_string(),
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 1);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 1);
    let result = &result.values[0];
    assert_eq!(result.name, did.name);
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

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .times(1)
        .returning(|_, _| Err(crate::repository::error::DataLayerError::RecordNotFound));
    did_repository
        .expect_create_did()
        .times(1)
        .returning(|request| Ok(request.id));

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

    let mut key_repository = MockKeyRepository::default();
    key_repository
        .expect_get_key()
        .times(1)
        .returning(move |_, _| {
            let key_pair = did_key::Ed25519KeyPair::new();
            Ok(Key {
                id: key_id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: key_pair.public_key_bytes(),
                name: "".to_string(),
                private_key: key_pair.private_key_bytes(),
                storage_type: "MOCK".to_string(),
                key_type: "".to_string(),
                organisation: None,
            })
        });
    let mut key_storage = MockKeyStorage::default();
    key_storage
        .expect_fingerprint()
        .times(1)
        .returning(move |_| Ok("did:key:MOCK".to_string()));

    let did_config = HashMap::<String, DidEntity>::from([(
        "KEY".to_string(),
        DidEntity {
            r#type: data_structure::DidType::Key,
            display: data_structure::TranslatableString::Key("translation".to_string()),
            order: None,
            params: None,
        },
    )]);
    let service = setup_service(
        did_repository,
        organisation_repository,
        key_repository,
        key_storage,
        did_config,
    );

    let result = service.create_did(create_request).await;
    result.unwrap();
}

#[tokio::test]
async fn test_create_did_value_already_exists() {
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

    let did = Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(Organisation {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
    };

    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did_by_value()
        .times(1)
        .returning(move |_, _| Ok(did.clone()));

    let mut key_repository = MockKeyRepository::default();
    key_repository
        .expect_get_key()
        .times(1)
        .returning(move |_, _| {
            let key_pair = did_key::Ed25519KeyPair::new();
            Ok(Key {
                id: key_id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: key_pair.public_key_bytes(),
                name: "".to_string(),
                private_key: key_pair.private_key_bytes(),
                storage_type: "MOCK".to_string(),
                key_type: "".to_string(),
                organisation: None,
            })
        });
    let mut key_storage = MockKeyStorage::default();
    key_storage
        .expect_fingerprint()
        .times(1)
        .returning(move |_| Ok("did:key:MOCK".to_string()));

    let did_config = HashMap::<String, DidEntity>::from([(
        "KEY".to_string(),
        DidEntity {
            r#type: data_structure::DidType::Key,
            display: data_structure::TranslatableString::Key("translation".to_string()),
            order: None,
            params: None,
        },
    )]);
    let service = setup_service(
        repository,
        MockOrganisationRepository::default(),
        key_repository,
        key_storage,
        did_config,
    );

    let result = service.create_did(create_request).await;
    assert!(matches!(result, Err(ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_create_did_value_invalid_did_method() {
    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did_type: DidType::Local,
        did_method: "UNKNOWN".to_string(),
        keys: CreateDidRequestKeysDTO {
            authentication: vec![],
            assertion: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        },
        params: None,
    };

    let did_config = HashMap::<String, DidEntity>::from([(
        "KEY".to_string(),
        DidEntity {
            r#type: data_structure::DidType::Key,
            display: data_structure::TranslatableString::Key("translation".to_string()),
            order: None,
            params: None,
        },
    )]);
    let service = setup_service(
        MockDidRepository::default(),
        MockOrganisationRepository::default(),
        MockKeyRepository::default(),
        MockKeyStorage::default(),
        did_config,
    );

    let result = service.create_did(create_request).await;
    assert!(matches!(
        result,
        Err(ServiceError::ConfigValidationError(_))
    ));
}
