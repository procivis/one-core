use super::DidService;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::service::error::BusinessLogicError;
use crate::service::test_utilities::dummy_did;
use crate::{
    config::core_config::{self, CoreConfig, DidConfig, Fields},
    model::{
        did::{Did, DidListQuery, DidRelations, DidType, GetDidList, KeyRole, RelatedKey},
        key::{Key, KeyRelations},
        list_query::ListPagination,
        organisation::{Organisation, OrganisationRelations},
    },
    provider::did_method::{provider::DidMethodProviderImpl, DidMethod, MockDidMethod},
    repository::mock::key_repository::MockKeyRepository,
    repository::{
        did_repository::MockDidRepository,
        mock::organisation_repository::MockOrganisationRepository,
    },
    service::{
        did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO},
        error::ServiceError,
    },
};
use mockall::predicate::*;
use shared_types::{DidId, DidValue};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(
    did_repository: MockDidRepository,
    key_repository: MockKeyRepository,
    organisation_repository: MockOrganisationRepository,
    did_method: MockDidMethod,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    did_config: DidConfig,
) -> DidService {
    let mut did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>> = HashMap::new();
    did_methods.insert("KEY".to_string(), Arc::new(did_method));

    let did_repository = Arc::new(did_repository);
    let did_method_provider = DidMethodProviderImpl::new(did_methods);

    DidService::new(
        did_repository,
        Arc::new(key_repository),
        Arc::new(organisation_repository),
        Arc::new(did_method_provider),
        Arc::new(key_algorithm_provider),
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
                key_reference: vec![],
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
        }]),
        deactivated: false,
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
            .returning(move |_, _| Ok(Some(did_clone.clone())));
    }

    let service = setup_service(
        repository,
        MockKeyRepository::default(),
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
    assert!(result.keys.assertion.is_empty());
}

#[tokio::test]
async fn test_get_did_missing() {
    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did()
        .times(1)
        .returning(|_, _| Ok(None));

    let service = setup_service(
        repository,
        MockKeyRepository::default(),
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
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
        deactivated: false,
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
            Ok(Key {
                id: key_id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: b"public".to_vec(),
                name: "".to_string(),
                key_reference: b"private".to_vec(),
                storage_type: "INTERNAL".to_string(),
                key_type: "".to_string(),
                organisation: None,
            })
        });

    let mut did_method = MockDidMethod::default();
    did_method
        .expect_create()
        .once()
        .returning(|_, _request, _key| Ok(DidValue::from_str("value").unwrap()));

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .once()
        .returning(|_, _| Err(crate::repository::error::DataLayerError::RecordNotFound));

    did_repository
        .expect_create_did()
        .once()
        .returning(move |_| Ok(DidId::from_str("788c8151-e62d-40bb-abd5-97483f426e66").unwrap()));

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .once()
        .returning(|id, _| {
            Ok(Organisation {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            })
        });

    let service = setup_service(
        did_repository,
        key_repository,
        organisation_repository,
        did_method,
        MockKeyAlgorithmProvider::default(),
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
            Ok(Key {
                id: key_id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: b"public".to_vec(),
                name: "".to_string(),
                key_reference: b"private".to_vec(),
                storage_type: "INTERNAL".to_string(),
                key_type: "".to_string(),
                organisation: None,
            })
        });

    let mut did_method = MockDidMethod::default();
    did_method
        .expect_create()
        .times(1)
        .returning(|_, _, _| Ok(DidValue::from_str("value").unwrap()));

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .once()
        .returning(|_, _| Ok(dummy_did()));

    let service = setup_service(
        did_repository,
        key_repository,
        MockOrganisationRepository::default(),
        did_method,
        MockKeyAlgorithmProvider::default(),
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
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
        get_did_config(),
    );

    let result = service.create_did(create_request).await;
    assert!(matches!(result, Err(ServiceError::IncorrectParameters)));
}
