use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use indexmap::IndexMap;
use mockall::predicate::*;
use serde_json::Value;
use shared_types::DidId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::DidService;
use crate::config::core_config::{self, CoreConfig, DidConfig, Fields, KeyAlgorithmType};
use crate::model::did::{
    Did, DidListQuery, DidRelations, DidType, GetDidList, KeyRole, RelatedKey,
};
use crate::model::key::{Key, KeyRelations};
use crate::model::list_query::ListPagination;
use crate::model::organisation::OrganisationRelations;
use crate::provider::caching_loader::CachingLoader;
use crate::provider::did_method::model::DidCapabilities;
use crate::provider::did_method::provider::DidMethodProviderImpl;
use crate::provider::did_method::{DidCreated, DidMethod, MockDidMethod};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::remote_entity_storage::RemoteEntityType;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::test_utilities::dummy_organisation;

fn setup_service(
    did_repository: MockDidRepository,
    key_repository: MockKeyRepository,
    identifier_repository: MockIdentifierRepository,
    organisation_repository: MockOrganisationRepository,
    did_method: MockDidMethod,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    did_config: DidConfig,
) -> DidService {
    let mut did_methods: IndexMap<String, Arc<dyn DidMethod>> = IndexMap::new();
    did_methods.insert("KEY".to_string(), Arc::new(did_method));

    let did_repository = Arc::new(did_repository);
    let did_caching_loader = CachingLoader::new(
        RemoteEntityType::DidDocument,
        Arc::new(InMemoryStorage::new(HashMap::new())),
        999,
        Duration::seconds(1000),
        Duration::seconds(999),
    );
    let did_method_provider = DidMethodProviderImpl::new(did_caching_loader, did_methods);
    let key_provider = MockKeyProvider::new();

    DidService::new(
        did_repository,
        Arc::new(key_repository),
        Arc::new(identifier_repository),
        Arc::new(organisation_repository),
        Arc::new(did_method_provider),
        Arc::new(key_algorithm_provider),
        Arc::new(key_provider),
        Arc::new(CoreConfig {
            did: did_config,
            ..CoreConfig::default()
        }),
    )
}

fn get_did_config() -> DidConfig {
    let mut config = DidConfig::default();

    config.insert(
        "KEY".to_string(),
        Fields {
            r#type: core_config::DidType::Key,
            display: Value::String("translation".to_string()),
            order: None,
            enabled: None,
            capabilities: None,
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
        organisation: Some(dummy_organisation(None)),
        did: "did:key:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: vec![],
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
        }]),
        deactivated: false,
        log: None,
    };
    {
        let did_clone = did.clone();
        repository
            .expect_get_did()
            .once()
            .with(
                eq(did.id.to_owned()),
                eq(DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    keys: Some(KeyRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(did_clone.clone())));
    }

    let service = setup_service(
        repository,
        MockKeyRepository::default(),
        MockIdentifierRepository::default(),
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
        DidConfig::default(),
    );

    let result = service.get_did(&did.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, did.id);
    assert_eq!(result.keys.authentication.len(), 1);
    assert!(result.keys.assertion_method.is_empty());
}

#[tokio::test]
async fn test_get_did_missing() {
    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did()
        .once()
        .returning(|_, _| Ok(None));

    let service = setup_service(
        repository,
        MockKeyRepository::default(),
        MockIdentifierRepository::default(),
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
        DidConfig::default(),
    );

    let result = service.get_did(&Uuid::new_v4().into()).await;
    assert2::assert!(
        let Err(ServiceError::EntityNotFound(
            EntityNotFoundError::Did(_)
        )) = result,
    );
}

#[tokio::test]
async fn test_get_did_list() {
    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(dummy_organisation(None)),
        did: "did:key:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
        deactivated: false,
        log: None,
    };

    let mut repository = MockDidRepository::default();
    {
        let did_clone = did.clone();
        repository.expect_get_did_list().once().returning(move |_| {
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
        MockIdentifierRepository::default(),
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
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
        organisation_id: Uuid::new_v4().into(),
        did_method: "KEY".to_string(),
        keys: CreateDidRequestKeysDTO {
            authentication: vec![key_id.into()],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        },
        params: None,
    };

    let mut key_repository = MockKeyRepository::default();
    key_repository.expect_get_keys().once().returning(move |_| {
        Ok(vec![Key {
            id: key_id.into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: b"public".to_vec(),
            name: "".to_string(),
            key_reference: b"private".to_vec(),
            storage_type: "INTERNAL".to_string(),
            key_type: "".to_string(),
            organisation: None,
        }])
    });

    let mut did_method = MockDidMethod::default();
    did_method.expect_validate_keys().once().returning(|_| true);

    did_method
        .expect_create()
        .once()
        .returning(|_, _request, _key| {
            Ok(DidCreated {
                did: "did:example:123".parse().unwrap(),
                log: None,
            })
        });

    did_method
        .expect_get_capabilities()
        .once()
        .returning(|| DidCapabilities {
            operations: vec![],
            key_algorithms: vec![KeyAlgorithmType::Eddsa],
            method_names: vec!["example".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_name()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let mut did_repository = MockDidRepository::default();

    did_repository
        .expect_create_did()
        .once()
        .returning(move |_| Ok(DidId::from_str("788c8151-e62d-40bb-abd5-97483f426e66").unwrap()));

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .once()
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_create()
        .once()
        .returning(|identifier| Ok(identifier.id));

    let service = setup_service(
        did_repository,
        key_repository,
        identifier_repository,
        organisation_repository,
        did_method,
        key_algorithm_provider,
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
        organisation_id: Uuid::new_v4().into(),
        did_method: "KEY".to_string(),
        keys: CreateDidRequestKeysDTO {
            authentication: vec![key_id.into()],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        },
        params: None,
    };

    let mut key_repository = MockKeyRepository::default();
    key_repository.expect_get_keys().once().returning(move |_| {
        Ok(vec![Key {
            id: key_id.into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: b"public".to_vec(),
            name: "".to_string(),
            key_reference: b"private".to_vec(),
            storage_type: "INTERNAL".to_string(),
            key_type: "".to_string(),
            organisation: None,
        }])
    });

    let mut did_method = MockDidMethod::default();
    did_method.expect_validate_keys().once().returning(|_| true);

    did_method.expect_create().once().returning(|_, _, _| {
        Ok(DidCreated {
            did: "did:example:123".parse().unwrap(),
            log: None,
        })
    });

    did_method
        .expect_get_capabilities()
        .once()
        .returning(|| DidCapabilities {
            operations: vec![],
            key_algorithms: vec![KeyAlgorithmType::Eddsa],
            method_names: vec!["example".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    key_algorithm_provider
        .expect_key_algorithm_from_name()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .return_once(|| KeyAlgorithmType::Eddsa);

            Some(Arc::new(key_algorithm))
        });

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .once()
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_create_did()
        .once()
        .returning(|_| Err(DataLayerError::AlreadyExists));

    let service = setup_service(
        did_repository,
        key_repository,
        MockIdentifierRepository::default(),
        organisation_repository,
        did_method,
        key_algorithm_provider,
        get_did_config(),
    );

    let result = service.create_did(create_request).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::DidValueAlreadyExists(_)
        ))
    ));
}

#[tokio::test]
async fn test_fail_to_create_did_value_invalid_amount_of_keys() {
    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4().into(),
        did_method: "KEY".to_string(),
        keys: CreateDidRequestKeysDTO {
            authentication: vec![Uuid::new_v4().into(), Uuid::new_v4().into()],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
        },
        params: None,
    };

    let mut did_method = MockDidMethod::default();
    did_method
        .expect_validate_keys()
        .once()
        .returning(|_| false);

    let service = setup_service(
        MockDidRepository::default(),
        MockKeyRepository::default(),
        MockIdentifierRepository::default(),
        MockOrganisationRepository::default(),
        did_method,
        MockKeyAlgorithmProvider::default(),
        get_did_config(),
    );

    let result = service.create_did(create_request).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::DidInvalidKeyNumber
        ))
    ));
}
