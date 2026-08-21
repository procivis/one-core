use std::sync::Arc;

use mockall::predicate::*;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::DidService;
use super::dto::{
    CreateDidRequestDTO, CreateDidRequestKeysDTO, DidFilterParamsDTO, DidPatchRequestDTO,
};
use super::error::DidServiceError;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::did::{Did, DidType, GetDidList, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::key::Key;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::provider::did_method::model::{DidCapabilities, Operation};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidUpdate, MockDidMethod};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::test_utilities::{dummy_did, dummy_identifier, dummy_organisation};

fn setup_service(
    did_repository: MockDidRepository,
    identifier_repository: MockIdentifierRepository,
    identifier_creator: MockIdentifierCreator,
    organisation_repository: MockOrganisationRepository,
    did_method: MockDidMethod,
    key_algorithm_provider: MockKeyAlgorithmProvider,
) -> DidService {
    let did_method = Arc::new(did_method);

    let did_repository = Arc::new(did_repository);
    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_did_method()
        .returning(move |_| Ok((did_method.clone(), crate::config::core_config::DidType::Key)));

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
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "name".to_string(),
        organisation: dummy_organisation(None).into(),
        did: "did:key:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: dummy_organisation(None).into(),
            },
            reference: "abc".to_string(),
        }]
        .into(),
        deactivated: false,
        log: None,
    };
    {
        let did_clone = did.clone();
        repository
            .expect_get_did()
            .once()
            .with(eq(did.id.to_owned()))
            .returning(move |_| Ok(did_clone.clone()));
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
    repository.expect_get_did().once().returning(|id| {
        Err(DataLayerError::EntityNotFound {
            kind: EntityKind::Did,
            id: (*id).into(),
        })
    });

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
        let Err(DidServiceError::NotFound(_)) = result,
    );
}

#[tokio::test]
async fn test_get_did_list() {
    let organisation_id = Uuid::new_v4().into();
    let did = Did {
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "name".to_string(),
        organisation: dummy_organisation(Some(organisation_id)).into(),
        did: "did:key:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: Default::default(),
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
        .get_did_list(ListQueryDTO {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            filter: DidFilterParamsDTO {
                name: None,
                did: None,
                r#type: None,
                exact: None,
                deactivated: None,
                key_algorithms: None,
                key_roles: None,
                key_storages: None,
                key_ids: None,
                did_methods: None,
                organisation_id,
            },
            include: None,
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
        did_method: "KEY".into(),
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
        .returning(|id| Ok(dummy_organisation(Some(*id))));

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_create_local_identifier()
        .once()
        .return_once(|_, _, _| {
            Ok(Identifier {
                data: IdentifierData::Did((dummy_did()).into()),
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
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "name".to_string(),
        organisation: dummy_organisation(None).into(),
        did: "did:web:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: Default::default(),
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
        move |_| Ok(clone.to_owned())
    });
    did_repository
        .expect_update_did()
        .once()
        .returning(|_, _| Ok(()));

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .once()
        .return_once(|_| Ok(Some(dummy_identifier())));
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
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "name".to_string(),
        organisation: dummy_organisation(None).into(),
        did: "did:web:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: Default::default(),
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
        move |_| Ok(clone.to_owned())
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
        Err(DidServiceError::CannotBeReactivated { .. })
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
        .get_did_list(ListQueryDTO {
            page: 0,
            page_size: 0,
            sort: None,
            sort_direction: None,
            filter: DidFilterParamsDTO {
                name: None,
                did: None,
                r#type: None,
                exact: None,
                deactivated: None,
                key_algorithms: None,
                key_roles: None,
                key_storages: None,
                key_ids: None,
                did_methods: None,
                organisation_id: Uuid::new_v4().into(),
            },
            include: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_did_ops_session_org_mismatch() {
    let did = Did {
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "name".to_string(),
        organisation: dummy_organisation(None).into(),
        did: "did:web:abc".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: Default::default(),
        deactivated: false,
        log: None,
    };
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .returning(move |_| Ok(did.clone()));
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
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service
        .update_did(
            &Uuid::new_v4().into(),
            DidPatchRequestDTO { deactivated: None },
        )
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}
