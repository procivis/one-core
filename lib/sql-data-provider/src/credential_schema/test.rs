use std::sync::Arc;

use one_core::clock::now_utc;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{
    BackgroundProperties, CredentialSchema, CredentialSchemaListQuery, LayoutProperties,
    UpdateCredentialSchemaRequest,
};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::Organisation;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::{
    MockOrganisationRepository, OrganisationRepository,
};
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set, Unchanged};
use shared_types::CredentialSchemaId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::CredentialSchemaProvider;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{credential_schema, organisation};
use crate::organisation::mapper::organisation_from_model;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

#[derive(Default)]
struct Repositories {
    pub organisation_repository: MockOrganisationRepository,
}

struct TestSetup {
    pub db: DatabaseConnection,
    pub organisation: Organisation,
    pub repository: Box<dyn CredentialSchemaRepository>,
}

async fn setup_empty(repositories: Repositories) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let organisation_repository: Arc<dyn OrganisationRepository> =
        Arc::from(repositories.organisation_repository);
    TestSetup {
        organisation: organisation_from_model(
            organisation::Entity::find_by_id(organisation_id)
                .one(&db)
                .await
                .expect("failed to load organisation")
                .expect("organisation not found"),
            &organisation_repository,
        ),
        repository: Box::new(CredentialSchemaProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository,
            localized_text_repository: data_layer.localized_text_repository,
        }),
        db,
    }
}

struct TestSetupWithCredentialSchema {
    pub db: DatabaseConnection,
    pub credential_schema: CredentialSchema,
    pub organisation: Organisation,
    pub repository: Box<dyn CredentialSchemaRepository>,
}

async fn setup_with_schema(repositories: Repositories) -> TestSetupWithCredentialSchema {
    let TestSetup {
        db,
        organisation,
        repository,
        ..
    } = setup_empty(repositories).await;

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation.id,
        "credential schema",
        false,
        None,
    )
    .await
    .unwrap();

    let credential_schema_format_id =
        insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
            .await
            .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: format!("key-{i}"),
            required: i % 2 == 0,
            order: i as u32,
            datatype: "STRING",
            array: false,
            metadata: false,
        })
        .collect();

    let claim_input = ProofInput {
        credential_schema_id,
        claims: &new_claim_schemas,
    };

    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    TestSetupWithCredentialSchema {
        credential_schema: CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            key_storage_security: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "credential schema".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: credential_schema_format_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credential_schema_id,
                format: "JWT".into(),
                schema_id: credential_schema_id.to_string(),
                claim_mappings: Default::default(),
            }]
            .into(),
            claim_schemas: new_claim_schemas
                .into_iter()
                .map(|claim| ClaimSchema {
                    id: claim.id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: claim.key.to_owned(),
                    data_type: claim.datatype.to_owned(),
                    array: false,
                    metadata: false,
                    required: claim.required,
                    translations: Default::default(),
                })
                .collect::<Vec<_>>()
                .into(),
            organisation: organisation.clone().into(),
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            embedded_disclosure_policy: None,
            translations: Default::default(),
        },
        organisation,
        repository,
        db,
    }
}

#[tokio::test]
async fn test_create_credential_schema_success() {
    let TestSetup {
        repository,
        organisation,
        db,
        ..
    } = setup_empty(Repositories::default()).await;

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let claim_schemas = vec![
        ClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            key: "key1".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            key: "key2".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            metadata: false,
            required: false,
            translations: Default::default(),
        },
    ];

    let result = repository
        .create_credential_schema(CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            key_storage_security: Some(KeyStorageSecurity::Basic.into()),
            imported_source_url: "CORE_URL".to_string(),
            name: "schema".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                last_modified: now_utc(),
                credential_schema_id,
                format: "JWT".into(),
                schema_id: "CredentialSchemaId".to_owned(),
                claim_mappings: Default::default(),
            }]
            .into(),
            claim_schemas: claim_schemas.into(),
            organisation: organisation.into(),
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_schema_id);

    assert_eq!(
        credential_schema::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::entity::claim_schema::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn test_create_credential_schema_already_exists() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository.create_credential_schema(credential_schema).await;
    assert!(matches!(result, Err(DataLayerError::AlreadyExists)));
}

#[tokio::test]
async fn test_get_credential_schema_list_success() {
    let TestSetupWithCredentialSchema {
        organisation,
        repository,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition(),
            ),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(1, result.total_pages);
    assert_eq!(1, result.total_items);
    assert_eq!(1, result.values.len());
}

#[tokio::test]
async fn test_get_credential_schema_list_deleted_schema() {
    let TestSetupWithCredentialSchema {
        organisation,
        repository,
        credential_schema,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    credential_schema::ActiveModel {
        id: Unchanged(credential_schema.id),
        deleted_at: Set(Some(get_dummy_date())),
        ..Default::default()
    }
    .update(&db)
    .await
    .unwrap();

    let result = repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition(),
            ),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(0, result.total_pages);
    assert_eq!(0, result.total_items);
    assert_eq!(0, result.values.len());
}

#[tokio::test]
async fn test_get_credential_schema_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        organisation,
        ..
    } = setup_with_schema(Default::default()).await;

    let result = repository
        .get_credential_schema(&credential_schema.id)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential_schema.id, result.id);
    let claim_schemas = result.claim_schemas.as_ref().await.unwrap();
    assert_eq!(claim_schemas.len(), 2);
    assert_eq!(organisation.id, result.organisation.id());

    let empty_relations_mean_no_other_repository_calls = repository
        .get_credential_schema(&credential_schema.id)
        .await;
    assert!(empty_relations_mean_no_other_repository_calls.is_ok());
}

#[tokio::test]
async fn test_get_credential_schema_deleted() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Default::default()).await;

    let delete_date = get_dummy_date();
    credential_schema::ActiveModel {
        id: Unchanged(credential_schema.id),
        deleted_at: Set(Some(delete_date)),
        ..Default::default()
    }
    .update(&db)
    .await
    .unwrap();

    let result = repository
        .get_credential_schema(&credential_schema.id)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, credential_schema.id);
    assert_eq!(result.deleted_at.unwrap(), delete_date);
}

#[tokio::test]
async fn test_get_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let result = repository
        .get_credential_schema(&Uuid::new_v4().into())
        .await;
    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
}

#[tokio::test]
async fn test_delete_credential_schema_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository
        .delete_credential_schema(&credential_schema)
        .await;
    assert!(result.is_ok());

    let db_schemas = credential_schema::Entity::find().all(&db).await.unwrap();
    assert_eq!(db_schemas.len(), 1);
    assert!(db_schemas[0].deleted_at.is_some());
}

#[tokio::test]
async fn test_delete_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let credential_schema_id = Uuid::new_v4().into();
    let result = repository
        .delete_credential_schema(&CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now_utc(),
            last_modified: now_utc(),
            name: "Test".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                last_modified: now_utc(),
                credential_schema_id,
                format: "MDOC".into(),
                schema_id: "Test_schema_id".to_owned(),
                claim_mappings: Default::default(),
            }]
            .into(),
            key_storage_security: None,
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_wallet_instance_attestation: false,
            claim_schemas: Default::default(),
            organisation: dummy_organisation(None).into(),
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        })
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated)));
}

#[tokio::test]
async fn test_update_credential_schema_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository
        .update_credential_schema(UpdateCredentialSchemaRequest {
            id: credential_schema.id,
            claim_schemas: None,
            layout_properties: Some(LayoutProperties {
                background: Some(BackgroundProperties {
                    color: Some("color".to_string()),
                    image: None,
                }),
                ..Default::default()
            }),
            claim_mappings: None,
        })
        .await;
    assert!(result.is_ok());

    let db_schemas = credential_schema::Entity::find().all(&db).await.unwrap();
    assert_eq!(db_schemas.len(), 1);
    assert_eq!(
        &db_schemas[0]
            .layout_properties
            .as_ref()
            .unwrap()
            .background
            .as_ref()
            .unwrap()
            .color,
        &Some("color".to_string())
    );
}

#[tokio::test]
async fn test_update_credential_schema_claims_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let now = now_utc();
    let claim_schema_id = Uuid::new_v4().into();
    let result = repository
        .update_credential_schema(UpdateCredentialSchemaRequest {
            id: credential_schema.id,
            claim_schemas: Some(vec![ClaimSchema {
                id: claim_schema_id,
                key: "new claim".to_string(),
                data_type: "STRING".to_string(),
                created_date: now,
                last_modified: now,
                array: false,
                metadata: false,
                required: false,
                translations: Default::default(),
            }]),
            layout_properties: None,
            claim_mappings: None,
        })
        .await;
    assert!(result.is_ok());
    let claim_schema = crate::entity::claim_schema::Entity::find_by_id(claim_schema_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_schema.order, 2);
}

#[tokio::test]
async fn test_get_by_schema_id_and_organisation() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let res = repository
        .get_by_schema_id_and_organisation(
            &credential_schema.schema_id().await.unwrap(),
            credential_schema.organisation.id(),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(res, credential_schema);
}
