use std::sync::Arc;

use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential_schema::{
    BackgroundProperties, CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations,
    GetCredentialSchemaQuery, LayoutProperties, LayoutType, UpdateCredentialSchemaRequest,
    WalletStorageTypeEnum,
};
use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::claim_schema_repository::MockClaimSchemaRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set, Unchanged};
use shared_types::CredentialSchemaId;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::CredentialSchemaProvider;
use crate::entity::credential_schema::WalletStorageType;
use crate::entity::{credential_schema, organisation};
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

#[derive(Default)]
struct Repositories {
    pub claim_schema_repository: MockClaimSchemaRepository,
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

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    TestSetup {
        organisation: Organisation::from(
            organisation::Entity::find_by_id(organisation_id)
                .one(&db)
                .await
                .expect("failed to load organisation")
                .expect("organisation not found"),
        ),
        repository: Box::new(CredentialSchemaProvider {
            db: TransactionManagerImpl::new(db.clone()),
            claim_schema_repository: Arc::from(repositories.claim_schema_repository),
            organisation_repository: Arc::from(repositories.organisation_repository),
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
        "JWT",
        "NONE",
        WalletStorageType::Software,
    )
    .await
    .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: "test",
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
            id: credential_schema_id,
            deleted_at: None,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "credential schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(
                new_claim_schemas
                    .into_iter()
                    .map(|claim| CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: claim.id,
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            key: claim.key.to_owned(),
                            data_type: claim.datatype.to_owned(),
                            array: false,
                            metadata: false,
                        },
                        required: claim.required,
                    })
                    .collect(),
            ),
            organisation: Some(organisation.clone()),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: credential_schema_id.to_string(),
            allow_suspension: true,
            requires_app_attestation: false,
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
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                key: "key1".to_string(),
                data_type: "STRING".to_string(),
                array: false,
                metadata: false,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                key: "key2".to_string(),
                data_type: "STRING".to_string(),
                array: false,
                metadata: false,
            },
            required: false,
        },
    ];

    let result = repository
        .create_credential_schema(CredentialSchema {
            id: credential_schema_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            imported_source_url: "CORE_URL".to_string(),
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(claim_schemas),
            organisation: Some(organisation),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "CredentialSchemaId".to_owned(),
            allow_suspension: true,
            requires_app_attestation: false,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_schema_id);

    assert_eq!(
        crate::entity::credential_schema::Entity::find()
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
        .get_credential_schema_list(
            GetCredentialSchemaQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 5,
                }),
                filtering: Some(
                    CredentialSchemaFilterValue::OrganisationId(organisation.id).condition(),
                ),
                ..Default::default()
            },
            &Default::default(),
        )
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
        .get_credential_schema_list(
            GetCredentialSchemaQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                filtering: Some(
                    CredentialSchemaFilterValue::OrganisationId(organisation.id).condition(),
                ),
                ..Default::default()
            },
            &Default::default(),
        )
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(0, result.total_pages);
    assert_eq!(0, result.total_items);
    assert_eq!(0, result.values.len());
}

#[tokio::test]
async fn test_get_credential_schema_success() {
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .withf(|ids, _| ids.len() == 2)
        .returning(|ids, _| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: format!("key{id}"),
                    data_type: "STRING".to_string(),
                    array: false,
                    metadata: false,
                })
                .collect())
        });

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        organisation,
        ..
    } = setup_with_schema(Repositories {
        claim_schema_repository,
        organisation_repository,
    })
    .await;

    let result = repository
        .get_credential_schema(
            &credential_schema.id,
            &CredentialSchemaRelations {
                claim_schemas: Some(ClaimSchemaRelations::default()),
                organisation: Some(OrganisationRelations::default()),
            },
        )
        .await;

    assert!(result.is_ok());
    let result = result.unwrap().unwrap();
    assert_eq!(credential_schema.id, result.id);
    let claim_schemas = result.claim_schemas.unwrap();
    assert_eq!(claim_schemas.len(), 2);
    assert_eq!(organisation.id, result.organisation.unwrap().id);

    let empty_relations_mean_no_other_repository_calls = repository
        .get_credential_schema(&credential_schema.id, &CredentialSchemaRelations::default())
        .await;
    assert!(empty_relations_mean_no_other_repository_calls.is_ok());
}

#[tokio::test]
async fn test_get_credential_schema_deleted() {
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .returning(|ids, _| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: format!("key{id}"),
                    data_type: "STRING".to_string(),
                    array: false,
                    metadata: false,
                })
                .collect())
        });

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories {
        claim_schema_repository,
        organisation_repository,
    })
    .await;

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
        .get_credential_schema(
            &credential_schema.id,
            &CredentialSchemaRelations {
                claim_schemas: Some(ClaimSchemaRelations::default()),
                organisation: Some(OrganisationRelations::default()),
            },
        )
        .await;

    assert!(result.is_ok());
    let result = result.unwrap().unwrap();
    assert_eq!(result.id, credential_schema.id,);
    assert_eq!(result.deleted_at.unwrap(), delete_date);
}

#[tokio::test]
async fn test_get_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let result = repository
        .get_credential_schema(
            &Uuid::new_v4().into(),
            &CredentialSchemaRelations::default(),
        )
        .await;
    assert!(matches!(result, Ok(None)));
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

    let db_schemas = crate::entity::credential_schema::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(db_schemas.len(), 1);
    assert!(db_schemas[0].deleted_at.is_some());
}

#[tokio::test]
async fn test_delete_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let result = repository
        .delete_credential_schema(&CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "Test".to_string(),
            format: "MDOC".to_string(),
            revocation_method: "NONE".to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Document,
            layout_properties: None,
            schema_id: "Test_schema_id".to_string(),
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_app_attestation: false,
            claim_schemas: None,
            organisation: None,
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

    let new_revocation_method = "new-method";
    let new_format = "new-format";
    let result = repository
        .update_credential_schema(UpdateCredentialSchemaRequest {
            id: credential_schema.id,
            revocation_method: Some(new_revocation_method.to_string()),
            format: Some(new_format.to_string()),
            claim_schemas: None,
            layout_properties: Some(LayoutProperties {
                background: Some(BackgroundProperties {
                    color: Some("color".to_string()),
                    image: None,
                }),
                ..Default::default()
            }),
            layout_type: Some(LayoutType::Document),
        })
        .await;
    assert!(result.is_ok());

    let db_schemas = crate::entity::credential_schema::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(db_schemas.len(), 1);
    assert_eq!(db_schemas[0].revocation_method, new_revocation_method);
    assert_eq!(db_schemas[0].format, new_format);
    assert_eq!(db_schemas[0].layout_type, LayoutType::Document.into());
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
async fn test_get_by_schema_id_and_organisation() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let res = repository
        .get_by_schema_id_and_organisation(
            &credential_schema.schema_id,
            credential_schema.organisation.as_ref().unwrap().id,
            &CredentialSchemaRelations {
                claim_schemas: Some(Default::default()),
                organisation: Some(Default::default()),
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert!(&res.claim_schemas.is_some());
    assert!(&res.organisation.is_some());

    assert_eq!(res, credential_schema);
}
