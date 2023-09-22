use super::DidService;
use crate::{
    config::{
        data_structure,
        data_structure::{CoreConfig, DidEntity},
    },
    model::did::{Did, DidRelations, DidType, GetDidList},
    repository::mock::did_repository::MockDidRepository,
    service::{
        did::dto::{CreateDidRequestDTO, GetDidQueryDTO},
        error::ServiceError,
    },
};
use mockall::predicate::*;
use std::{collections::HashMap, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(
    did_repository: MockDidRepository,
    did_config: HashMap<String, DidEntity>,
) -> DidService {
    DidService::new(
        Arc::new(did_repository),
        Arc::new(CoreConfig {
            format: HashMap::default(),
            exchange: HashMap::default(),
            transport: HashMap::default(),
            revocation: HashMap::default(),
            did: did_config,
            datatype: HashMap::default(),
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
        organisation_id: Uuid::new_v4(),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
    };
    {
        let did_clone = did.clone();
        repository
            .expect_get_did()
            .times(1)
            .with(eq(did.id.to_owned()), eq(DidRelations::default()))
            .returning(move |_, _| Ok(did_clone.clone()));
    }

    let service = setup_service(repository, HashMap::<String, DidEntity>::new());

    let result = service.get_did(&did.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, did.id);
}

#[tokio::test]
async fn test_get_did_missing() {
    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did()
        .times(1)
        .returning(|_, _| Err(crate::repository::error::DataLayerError::RecordNotFound));

    let service = setup_service(repository, HashMap::<String, DidEntity>::new());

    let result = service.get_did(&Uuid::new_v4()).await;
    assert!(matches!(result, Err(ServiceError::NotFound)));
}

#[tokio::test]
async fn test_get_did_by_value_exists() {
    let mut repository = MockDidRepository::default();

    let did = Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
    };
    {
        let did_clone = did.clone();
        repository
            .expect_get_did_by_value()
            .times(1)
            .with(eq(did.did.to_owned()), eq(DidRelations::default()))
            .returning(move |_, _| Ok(did_clone.clone()));
    }

    let service = setup_service(repository, HashMap::<String, DidEntity>::new());

    let result = service.get_did_by_value(&did.did).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, did.id);
}

#[tokio::test]
async fn test_get_did_by_value_missing() {
    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did_by_value()
        .times(1)
        .returning(|_, _| Err(crate::repository::error::DataLayerError::RecordNotFound));

    let service = setup_service(repository, HashMap::<String, DidEntity>::new());

    let result = service.get_did_by_value(&"test".to_string()).await;
    assert!(matches!(result, Err(ServiceError::NotFound)));
}

#[tokio::test]
async fn test_get_did_list() {
    let did = Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
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

    let service = setup_service(repository, HashMap::<String, DidEntity>::new());

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
    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
    };

    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did_by_value()
        .times(1)
        .returning(|_, _| Err(crate::repository::error::DataLayerError::RecordNotFound));
    repository
        .expect_create_did()
        .times(1)
        .returning(|request| Ok(request.id));

    let did_config = HashMap::<String, DidEntity>::from([(
        "KEY".to_string(),
        DidEntity {
            r#type: data_structure::DidType::Key,
            display: data_structure::TranslatableString::Key("translation".to_string()),
            order: None,
            params: None,
        },
    )]);
    let service = setup_service(repository, did_config);

    let result = service.create_did(create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_did_value_already_exists() {
    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
    };

    let did = Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
    };

    let mut repository = MockDidRepository::default();
    repository
        .expect_get_did_by_value()
        .times(1)
        .with(
            eq(create_request.did.to_owned()),
            eq(DidRelations::default()),
        )
        .returning(move |_, _| Ok(did.clone()));

    let did_config = HashMap::<String, DidEntity>::from([(
        "KEY".to_string(),
        DidEntity {
            r#type: data_structure::DidType::Key,
            display: data_structure::TranslatableString::Key("translation".to_string()),
            order: None,
            params: None,
        },
    )]);
    let service = setup_service(repository, did_config);

    let result = service.create_did(create_request).await;
    assert!(matches!(result, Err(ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_create_did_value_invalid_did_method() {
    let create_request = CreateDidRequestDTO {
        name: "name".to_string(),
        organisation_id: Uuid::new_v4(),
        did: "did:key:abc".to_string(),
        did_type: DidType::Local,
        did_method: "UNKNOWN".to_string(),
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
    let service = setup_service(MockDidRepository::default(), did_config);

    let result = service.create_did(create_request).await;
    assert!(matches!(
        result,
        Err(ServiceError::ConfigValidationError(_))
    ));
}
