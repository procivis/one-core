use std::collections::HashMap;
use std::sync::Arc;

use indexmap::IndexMap;
use mockall::predicate::*;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::DidService;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::did::{
    Did, DidListQuery, DidRelations, DidType, GetDidList, KeyRole, RelatedKey,
};
use crate::model::identifier::Identifier;
use crate::model::key::{Key, KeyRelations};
use crate::model::list_query::ListPagination;
use crate::model::organisation::OrganisationRelations;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::provider::caching_loader::CachingLoader;
use crate::provider::did_method::model::{DidCapabilities, Operation};
use crate::provider::did_method::provider::{DidMethodProviderImpl, MockDidMethodProvider};
use crate::provider::did_method::{DidMethod, DidUpdate, MockDidMethod};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::remote_entity_storage::RemoteEntityType;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::did::DidDeactivationError;
use crate::service::did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO, DidPatchRequestDTO};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::test_utilities::{dummy_did, dummy_identifier, dummy_organisation};

fn setup_service(
    did_repository: MockDidRepository,
    identifier_repository: MockIdentifierRepository,
    identifier_creator: MockIdentifierCreator,
    organisation_repository: MockOrganisationRepository,
    did_method: MockDidMethod,
    key_algorithm_provider: MockKeyAlgorithmProvider,
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

    DidService::new(
        did_repository,
        Arc::new(identifier_repository),
        Arc::new(organisation_repository),
        Arc::new(did_method_provider),
        Arc::new(key_algorithm_provider),
        Arc::new(identifier_creator),
        Arc::new(NoSessionProvider),
    )
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
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "abc".to_string(),
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
        MockIdentifierRepository::default(),
        MockIdentifierCreator::default(),
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
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
        MockIdentifierRepository::default(),
        MockIdentifierCreator::default(),
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
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
    let organisation_id = Uuid::new_v4().into();
    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(dummy_organisation(Some(organisation_id))),
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
        MockIdentifierRepository::default(),
        MockIdentifierCreator::default(),
        MockOrganisationRepository::default(),
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
    );

    let result = service
        .get_did_list(
            &organisation_id,
            DidListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                ..Default::default()
            },
        )
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

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .once()
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_create_local_identifier()
        .once()
        .return_once(|_, _, _| {
            Ok(Identifier {
                did: Some(dummy_did()),
                ..dummy_identifier()
            })
        });

    let service = setup_service(
        MockDidRepository::default(),
        MockIdentifierRepository::default(),
        identifier_creator,
        organisation_repository,
        MockDidMethod::default(),
        MockKeyAlgorithmProvider::default(),
    );

    let result = service.create_did(create_request).await;
    result.unwrap();
}

#[tokio::test]
async fn test_update_did() {
    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(dummy_organisation(None)),
        did: "did:web:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: Some(vec![]),
        deactivated: false,
        log: None,
    };

    let update_request = DidPatchRequestDTO {
        deactivated: Some(true),
    };

    let mut did_method = MockDidMethod::default();
    did_method.expect_deactivate().once().returning(|_, _, _| {
        Ok(DidUpdate {
            deactivated: Some(true),
            log: None,
        })
    });
    did_method
        .expect_get_capabilities()
        .returning(|| DidCapabilities {
            operations: vec![Operation::DEACTIVATE],
            key_algorithms: vec![KeyAlgorithmType::Eddsa],
            method_names: vec!["example".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        });

    let mut did_repository = MockDidRepository::default();
    did_repository.expect_get_did().once().returning({
        let clone = did.to_owned();
        move |_, _| Ok(Some(clone.to_owned()))
    });
    did_repository
        .expect_update_did()
        .once()
        .returning(|_| Ok(()));

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .once()
        .return_once(|_, _| Ok(Some(dummy_identifier())));
    identifier_repository
        .expect_update()
        .once()
        .return_once(|_, _| Ok(()));

    let service = setup_service(
        did_repository,
        identifier_repository,
        MockIdentifierCreator::default(),
        MockOrganisationRepository::default(),
        did_method,
        MockKeyAlgorithmProvider::default(),
    );

    service.update_did(&did.id, update_request).await.unwrap();
}

#[tokio::test]
async fn test_update_did_fail_reactivation() {
    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(dummy_organisation(None)),
        did: "did:web:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: Some(vec![]),
        deactivated: true,
        log: None,
    };

    let update_request = DidPatchRequestDTO {
        deactivated: Some(false),
    };

    let mut did_method = MockDidMethod::default();
    did_method
        .expect_get_capabilities()
        .returning(|| DidCapabilities {
            operations: vec![Operation::DEACTIVATE],
            key_algorithms: vec![KeyAlgorithmType::Eddsa],
            method_names: vec!["example".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        });

    let mut did_repository = MockDidRepository::default();
    did_repository.expect_get_did().once().returning({
        let clone = did.to_owned();
        move |_, _| Ok(Some(clone.to_owned()))
    });

    let service = setup_service(
        did_repository,
        MockIdentifierRepository::default(),
        MockIdentifierCreator::default(),
        MockOrganisationRepository::default(),
        did_method,
        MockKeyAlgorithmProvider::default(),
    );

    let result = service.update_did(&did.id, update_request).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::DidDeactivation(DidDeactivationError::CannotBeReactivated { .. })
        ))
    ));
}

#[tokio::test]
async fn test_list_did_fail_session_org_mismatch() {
    let service = DidService {
        did_repository: Arc::new(MockDidRepository::default()),
        identifier_creator: Arc::new(MockIdentifierCreator::default()),
        identifier_repository: Arc::new(MockIdentifierRepository::default()),
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        did_method_provider: Arc::new(MockDidMethodProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service
        .get_did_list(
            &Uuid::new_v4().into(),
            DidListQuery {
                pagination: None,
                sorting: None,
                filtering: None,
                include: None,
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_did_ops_session_org_mismatch() {
    let did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation: Some(dummy_organisation(None)),
        did: "did:web:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
        deactivated: false,
        log: None,
    };
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .returning(move |_, _| Ok(Some(did.clone())));
    let service = DidService {
        did_repository: Arc::new(did_repository),
        identifier_creator: Arc::new(MockIdentifierCreator::default()),
        identifier_repository: Arc::new(MockIdentifierRepository::default()),
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        did_method_provider: Arc::new(MockDidMethodProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_did(&Uuid::new_v4().into()).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
    let result = service
        .update_did(
            &Uuid::new_v4().into(),
            DidPatchRequestDTO { deactivated: None },
        )
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}
