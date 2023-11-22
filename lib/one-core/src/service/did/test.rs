use super::DidService;
use crate::{
    config::core_config::{self, CoreConfig, DidConfig, Fields},
    model::{
        did::{Did, DidListQuery, DidRelations, DidType, GetDidList, KeyRole, RelatedKey},
        key::{Key, KeyRelations},
        list_query::ListPagination,
        organisation::{Organisation, OrganisationRelations},
    },
    provider::did_method::{
        provider::DidMethodProviderImpl, DidMethod, DidMethodError, MockDidMethod,
    },
    repository::did_repository::MockDidRepository,
    repository::mock::key_repository::MockKeyRepository,
    service::{
        did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO},
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
    key_repository: MockKeyRepository,
    did_method: MockDidMethod,
    did_config: DidConfig,
) -> DidService {
    let mut did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>> = HashMap::new();
    did_methods.insert("KEY".to_string(), Arc::new(did_method));

    let did_repository = Arc::new(did_repository);
    let did_method_provider = DidMethodProviderImpl::new(did_methods);

    DidService::new(
        did_repository,
        Arc::new(key_repository),
        Arc::new(did_method_provider),
        Arc::new(CoreConfig {
            did: did_config,
            ..CoreConfig::default()
        }),
    )
}

fn get_did_config() -> DidConfig {
    let mut config = DidConfig::default();

    config.insert(
        core_config::DidType::Key,
        Fields {
            r#type: "KEY".to_string(),
            display: "translation".to_string(),
            order: None,
            disabled: None,
            params: None,
        },
    );

    config
}

#[tokio::test]
async fn test_get_did_exists() {
    let mut repository = MockDidRepository::default();

    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(Organisation {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
        did: "did:key:abc".parse().unwrap(),
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
        MockKeyRepository::default(),
        MockDidMethod::default(),
        DidConfig::default(),
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
        MockKeyRepository::default(),
        MockDidMethod::default(),
        DidConfig::default(),
    );

    let result = service.get_did(&Uuid::new_v4().into()).await;
    assert!(matches!(result, Err(ServiceError::NotFound)));
}

#[tokio::test]
async fn test_get_did_list() {
    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(Organisation {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
        did: "did:key:abc".parse().unwrap(),
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
        MockKeyRepository::default(),
        MockDidMethod::default(),
        DidConfig::default(),
    );

    let result = service
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            ..Default::default()
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
                storage_type: "INTERNAL".to_string(),
                key_type: "".to_string(),
                organisation: None,
            })
        });

    let mut did_method = MockDidMethod::default();
    did_method
        .expect_create()
        .times(1)
        .returning(|_request, _key| Ok(Uuid::new_v4().into()));

    let service = setup_service(
        MockDidRepository::default(),
        key_repository,
        did_method,
        get_did_config(),
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
                storage_type: "INTERNAL".to_string(),
                key_type: "".to_string(),
                organisation: None,
            })
        });

    let mut did_method = MockDidMethod::default();
    did_method
        .expect_create()
        .times(1)
        .returning(|_, _| Err(DidMethodError::AlreadyExists));

    let service = setup_service(
        MockDidRepository::default(),
        key_repository,
        did_method,
        get_did_config(),
    );

    let result = service.create_did(create_request).await;
    assert!(matches!(
        result,
        Err(ServiceError::DidMethodError(DidMethodError::AlreadyExists))
    ));
}

#[tokio::test]
async fn test_create_did_value_invalid_did_method() {
    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: CreateDidRequestKeysDTO {
            authentication: vec![],
            assertion: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        },
        params: None,
    };

    let service = setup_service(
        MockDidRepository::default(),
        MockKeyRepository::default(),
        MockDidMethod::default(),
        get_did_config(),
    );

    let result = service.create_did(create_request).await;
    assert!(matches!(result, Err(ServiceError::IncorrectParameters)));
}
