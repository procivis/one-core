use super::ProofSchemaProvider;
use crate::{entity::proof_schema, test_utilities::*};
use one_core::model::credential_schema::WalletStorageTypeEnum;
use one_core::{
    model::{
        claim_schema::ClaimSchema,
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        organisation::{Organisation, OrganisationId, OrganisationRelations},
        proof_schema::{
            GetProofSchemaQuery, ProofSchema, ProofSchemaClaim, ProofSchemaClaimRelations,
            ProofSchemaId, ProofSchemaRelations,
        },
    },
    repository::{
        claim_schema_repository::{self, ClaimSchemaRepository},
        credential_schema_repository::MockCredentialSchemaRepository,
        credential_schema_repository::{self, CredentialSchemaRepository},
        error::DataLayerError,
        mock::{
            claim_schema_repository::MockClaimSchemaRepository,
            organisation_repository::MockOrganisationRepository,
        },
        organisation_repository::{self, OrganisationRepository},
        proof_schema_repository::ProofSchemaRepository,
    },
};
use sea_orm::{ActiveModelTrait, Set, Unchanged};
use std::{boxed::Box, sync::Arc};
use time::OffsetDateTime;
use uuid::Uuid;

struct TestSetup {
    pub repository: Box<dyn ProofSchemaRepository>,
    pub organisation_id: OrganisationId,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup_empty(
    claim_schema_repository: Arc<dyn claim_schema_repository::ClaimSchemaRepository>,
    organisation_repository: Arc<dyn organisation_repository::OrganisationRepository>,
    credential_schema_repository: Arc<dyn credential_schema_repository::CredentialSchemaRepository>,
) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    TestSetup {
        repository: Box::from(ProofSchemaProvider {
            db: db.clone(),
            claim_schema_repository,
            organisation_repository,
            credential_schema_repository,
        }),
        organisation_id: Uuid::parse_str(&organisation_id).unwrap(),
        db,
    }
}

struct TestSetupWithProofSchema {
    pub repository: Box<dyn ProofSchemaRepository>,
    pub proof_schema_name: String,
    pub proof_schema_id: ProofSchemaId,
    pub organisation_id: OrganisationId,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup_with_proof_schema(
    claim_schema_repository: Arc<dyn claim_schema_repository::ClaimSchemaRepository>,
    organisation_repository: Arc<dyn organisation_repository::OrganisationRepository>,
    credential_schema_repository: Arc<dyn credential_schema_repository::CredentialSchemaRepository>,
) -> TestSetupWithProofSchema {
    let TestSetup {
        repository,
        organisation_id,
        db,
        ..
    } = setup_empty(
        claim_schema_repository,
        organisation_repository,
        credential_schema_repository,
    )
    .await;

    let proof_schema_name = "proof schema".to_string();

    let proof_schema_id = Uuid::parse_str(
        &insert_proof_schema_to_database(
            &db,
            None,
            &organisation_id.to_string(),
            &proof_schema_name,
        )
        .await
        .unwrap(),
    )
    .unwrap();

    TestSetupWithProofSchema {
        repository,
        proof_schema_name,
        proof_schema_id,
        organisation_id,
        db,
    }
}

fn get_claim_schema_repository_mock() -> Arc<dyn ClaimSchemaRepository> {
    Arc::from(MockClaimSchemaRepository::default())
}

fn get_organisation_repository_mock() -> Arc<dyn OrganisationRepository> {
    Arc::from(MockOrganisationRepository::default())
}

fn get_credential_schema_repository_mock() -> Arc<dyn CredentialSchemaRepository> {
    Arc::from(MockCredentialSchemaRepository::default())
}

#[tokio::test]
async fn test_create_proof_schema_invalid_params() {
    let TestSetupWithProofSchema {
        repository,
        proof_schema_id,
        ..
    } = setup_with_proof_schema(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let result = repository
        .create_proof_schema(ProofSchema {
            id: proof_schema_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "test".to_string(),
            expire_duration: 0,
            claim_schemas: None,
            organisation: None,
            validity_constraint: None,
            input_schemas: None,
        })
        .await;

    assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
}

#[tokio::test]
async fn test_create_proof_schema_already_exists() {
    let TestSetupWithProofSchema {
        repository,
        proof_schema_id,
        organisation_id,
        ..
    } = setup_with_proof_schema(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let result = repository
        .create_proof_schema(ProofSchema {
            id: proof_schema_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            validity_constraint: None,
            name: "test".to_string(),
            expire_duration: 0,
            claim_schemas: Some(vec![ProofSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4(),
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                },
                required: false,
                credential_schema: None,
            }]),
            organisation: Some(Organisation {
                id: organisation_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }),
            input_schemas: None,
        })
        .await;

    assert!(matches!(result, Err(DataLayerError::AlreadyExists)));
}

#[tokio::test]
async fn test_create_proof_schema_success() {
    let TestSetup {
        repository,
        organisation_id,
        db,
        ..
    } = setup_empty(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let cred_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        &organisation_id.to_string(),
        "cred-schema",
        "JWT",
        "NONE",
    )
    .await
    .unwrap();

    let claim_schemas: Vec<(Uuid, &str, bool, u32, &str)> = (0..5)
        .map(|i| (Uuid::new_v4(), "test", i % 2 == 0, i, "STRING"))
        .collect();

    insert_many_claims_schema_to_database(&db, &cred_schema_id, &claim_schemas)
        .await
        .unwrap();

    let id = Uuid::new_v4();
    let result = repository
        .create_proof_schema(ProofSchema {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "test".to_string(),
            expire_duration: 0,
            validity_constraint: None,
            claim_schemas: Some(vec![ProofSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schemas[0].0,
                    key: "TestKey".to_string(),
                    data_type: claim_schemas[0].3.to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                },
                required: false,
                credential_schema: None,
            }]),
            organisation: Some(Organisation {
                id: organisation_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }),
            input_schemas: None,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);

    let db_schema = get_proof_schema_with_id(&db, &id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(db_schema.name, "test");
    assert_eq!(db_schema.expire_duration, 0);
    assert_eq!(db_schema.deleted_at, None);
}

#[tokio::test]
async fn test_delete_proof_schema_existing() {
    let TestSetupWithProofSchema {
        repository,
        proof_schema_id,
        proof_schema_name,
        db,
        ..
    } = setup_with_proof_schema(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let deleted_time = get_dummy_date();
    let result = repository
        .delete_proof_schema(&proof_schema_id, deleted_time)
        .await;

    assert!(result.is_ok());

    let deleted_schema = get_proof_schema_with_id(&db, &proof_schema_id.to_string())
        .await
        .unwrap();
    assert!(deleted_schema.is_some());
    let deleted_schema = deleted_schema.unwrap();

    assert!(deleted_schema.deleted_at.is_some());
    assert_eq!(deleted_time, deleted_schema.deleted_at.unwrap());
    assert_eq!(proof_schema_name, deleted_schema.name);
}

#[tokio::test]
async fn test_delete_proof_schema_twice() {
    let TestSetupWithProofSchema {
        repository,
        proof_schema_id,
        ..
    } = setup_with_proof_schema(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let result = repository
        .delete_proof_schema(&proof_schema_id, get_dummy_date())
        .await;
    assert!(result.is_ok());

    let result = repository
        .delete_proof_schema(&proof_schema_id, get_dummy_date())
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated)));
}

#[tokio::test]
async fn test_delete_proof_schema_missing() {
    let TestSetup { repository, .. } = setup_empty(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let result = repository
        .delete_proof_schema(&Uuid::new_v4(), get_dummy_date())
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated)));
}

#[tokio::test]
async fn test_get_proof_schema_missing() {
    let TestSetup { repository, .. } = setup_empty(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof_schema(&Uuid::new_v4(), &ProofSchemaRelations::default())
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_proof_schema_no_relations() {
    let TestSetupWithProofSchema {
        repository,
        proof_schema_id,
        proof_schema_name,
        ..
    } = setup_with_proof_schema(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof_schema(&proof_schema_id, &ProofSchemaRelations::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.id, proof_schema_id);
    assert_eq!(result.name, proof_schema_name);
}

#[tokio::test]
async fn test_get_proof_schema_deleted() {
    let TestSetupWithProofSchema {
        repository,
        proof_schema_id,
        db,
        ..
    } = setup_with_proof_schema(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let delete_date = get_dummy_date();
    proof_schema::ActiveModel {
        id: Unchanged(proof_schema_id.to_string()),
        deleted_at: Set(Some(delete_date)),
        ..Default::default()
    }
    .update(&db)
    .await
    .unwrap();

    let result = repository
        .get_proof_schema(&proof_schema_id, &ProofSchemaRelations::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.id, proof_schema_id);
    assert_eq!(result.deleted_at.unwrap(), delete_date);
}

#[tokio::test]
async fn test_get_proof_schema_with_relations() {
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .returning(|ids, _| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                })
                .collect())
        });

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| {
            Ok(Some(Organisation {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }))
        });

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema()
        .times(2)
        .returning(|id, _| {
            Ok(Some(CredentialSchema {
                id: id.to_owned(),
                deleted_at: None,
                wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "schema".to_string(),
                format: "JWT".to_string(),
                revocation_method: "NONE".to_string(),
                claim_schemas: None,
                organisation: None,
            }))
        });

    let TestSetup {
        repository,
        organisation_id,
        db,
        ..
    } = setup_empty(
        Arc::from(claim_schema_repository),
        Arc::from(organisation_repository),
        Arc::from(credential_schema_repository),
    )
    .await;

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        &organisation_id.to_string(),
        "credential schema",
        "JWT",
        "NONE",
    )
    .await
    .unwrap();

    let new_claim_schemas: Vec<(Uuid, &str, bool, u32, &str)> = (0..2)
        .map(|i| (Uuid::new_v4(), "test", i % 2 == 0, i as u32, "STRING"))
        .collect();
    insert_many_claims_schema_to_database(&db, &credential_schema_id, &new_claim_schemas)
        .await
        .unwrap();

    let proof_schema_id = Uuid::parse_str(
        &insert_proof_schema_with_claims_to_database(
            &db,
            None,
            &new_claim_schemas,
            &organisation_id.to_string(),
            "proof schema",
        )
        .await
        .unwrap(),
    )
    .unwrap();

    let result = repository
        .get_proof_schema(
            &proof_schema_id,
            &ProofSchemaRelations {
                claim_schemas: Some(ProofSchemaClaimRelations {
                    credential_schema: Some(CredentialSchemaRelations::default()),
                }),
                organisation: Some(OrganisationRelations::default()),
                proof_inputs: None,
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.id, proof_schema_id);

    assert!(result.organisation.is_some());
    assert_eq!(result.organisation.unwrap().id, organisation_id);

    assert!(result.claim_schemas.is_some());
    let claim_schemas = result.claim_schemas.unwrap();
    assert_eq!(claim_schemas.len(), 2);
    assert_eq!(claim_schemas[0].schema.id, new_claim_schemas[0].0);
    assert_eq!(claim_schemas[1].schema.id, new_claim_schemas[1].0);

    assert!(claim_schemas[0].credential_schema.is_some());
    let credential_schema = claim_schemas[0].credential_schema.as_ref().unwrap();
    assert_eq!(credential_schema.id.to_string(), credential_schema_id);
}

#[tokio::test]
async fn test_get_proof_schema_list_empty() {
    let TestSetup {
        repository,
        organisation_id,
        ..
    } = setup_empty(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 1,
            sort: None,
            exact: None,
            sort_direction: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 0);
    assert_eq!(result.total_pages, 0);
    assert_eq!(result.values.len(), 0);
}

#[tokio::test]
async fn test_get_proof_schema_list_deleted() {
    let TestSetupWithProofSchema {
        repository,
        organisation_id,
        proof_schema_id,
        ..
    } = setup_with_proof_schema(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    repository
        .delete_proof_schema(&proof_schema_id, get_dummy_date())
        .await
        .unwrap();

    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 1,
            sort: None,
            exact: None,
            sort_direction: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 0);
    assert_eq!(result.total_pages, 0);
    assert_eq!(result.values.len(), 0);
}

#[tokio::test]
async fn test_get_proof_schema_list_sorting_filtering_pagination() {
    let TestSetup {
        repository,
        organisation_id,
        db,
        ..
    } = setup_empty(
        get_claim_schema_repository_mock(),
        get_organisation_repository_mock(),
        get_credential_schema_repository_mock(),
    )
    .await;

    let date_now = OffsetDateTime::now_utc();
    let schema1_id = Uuid::parse_str(
        &crate::entity::proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(date_now),
            last_modified: Set(date_now),
            validity_constraint: Set(None),
            name: Set("schema-1".to_string()),
            expire_duration: Set(Default::default()),
            organisation_id: Set(organisation_id.to_string()),
            deleted_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap()
        .id,
    )
    .unwrap();

    let date_later = date_now + time::Duration::seconds(1);
    let schema2_id = Uuid::parse_str(
        &crate::entity::proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(date_later),
            last_modified: Set(date_later),
            validity_constraint: Set(None),
            name: Set("schema-2".to_string()),
            expire_duration: Set(Default::default()),
            organisation_id: Set(organisation_id.to_string()),
            deleted_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap()
        .id,
    )
    .unwrap();

    // default sorting - by created date descending
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            exact: None,
            sort: None,
            sort_direction: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 2);
    assert_eq!(result.values[0].id, schema2_id);

    // =========== SORTING
    // sort by name - default (ascending)
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            sort: Some(one_core::model::proof_schema::SortableProofSchemaColumn::Name),
            sort_direction: None,
            exact: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;
    assert_eq!(result.unwrap().values[0].id, schema1_id);

    // sort by name - descending
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            sort: Some(one_core::model::proof_schema::SortableProofSchemaColumn::Name),
            sort_direction: Some(one_core::model::common::SortDirection::Descending),
            exact: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;
    assert_eq!(result.unwrap().values[0].id, schema2_id);

    // sort by created-date - ascending
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            sort: Some(one_core::model::proof_schema::SortableProofSchemaColumn::CreatedDate),
            sort_direction: Some(one_core::model::common::SortDirection::Ascending),
            exact: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;
    assert_eq!(result.unwrap().values[0].id, schema1_id);

    // =========== FILTERING
    // filter by name - one result
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: None,
            sort_direction: None,
            name: Some("schema-1".to_string()),
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 1);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema1_id);

    // filter by name - two results
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: None,
            sort_direction: None,
            name: Some("schema".to_string()),
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 2);

    // filter by name - no results
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: None,
            sort_direction: None,
            name: Some("nothing".to_string()),
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 0);
    assert_eq!(result.total_pages, 0);
    assert_eq!(result.values.len(), 0);

    // ====== PAGINATION
    // first page
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            exact: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 2);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema2_id);

    // second page
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 1,
            page_size: 1,
            sort: None,
            exact: None,
            sort_direction: None,
            name: None,
            organisation_id: organisation_id.to_string(),
            ids: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 2);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema1_id);
}
