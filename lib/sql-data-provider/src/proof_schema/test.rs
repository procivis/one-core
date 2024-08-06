use std::sync::Arc;

use one_providers::common_models::credential_schema::WalletStorageTypeEnum;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType, LayoutType,
};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::model::proof_schema::{
    GetProofSchemaQuery, ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations,
    ProofSchema, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use one_core::repository::claim_schema_repository::{
    self, ClaimSchemaRepository, MockClaimSchemaRepository,
};
use one_core::repository::credential_schema_repository::{
    self, CredentialSchemaRepository, MockCredentialSchemaRepository,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::{
    self, MockOrganisationRepository, OrganisationRepository,
};
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use sea_orm::{ActiveModelTrait, Set, Unchanged};
use shared_types::{OrganisationId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofSchemaProvider;
use crate::entity::proof_schema;
use crate::test_utilities::*;

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
        organisation_id,
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

    let proof_schema_id =
        insert_proof_schema_to_database(&db, None, organisation_id, &proof_schema_name)
            .await
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
            organisation: None,
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
            name: "test".to_string(),
            expire_duration: 0,
            organisation: Some(Organisation {
                id: organisation_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }),
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "key".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                    },
                    required: false,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    deleted_at: None,
                    wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    organisation: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                    schema_id: "CredentialSchemaId".to_owned(),
                }),
            }]),
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

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "cred-schema",
        "JWT",
        "NONE",
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
        })
        .collect();

    let claim_input = ProofInput {
        credential_schema_id,
        claims: &new_claim_schemas,
    };

    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    let id = Uuid::new_v4().into();
    let result = repository
        .create_proof_schema(ProofSchema {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "test".to_string(),
            expire_duration: 0,
            organisation: Some(Organisation {
                id: organisation_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }),
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: new_claim_schemas[0].id,
                        key: "TestKey".to_string(),
                        data_type: new_claim_schemas[0].datatype.to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                    },
                    required: false,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: credential_schema_id,
                    deleted_at: None,
                    wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    organisation: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                    schema_id: "CredentialSchemaId".to_owned(),
                }),
            }]),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);

    let db_schema = get_proof_schema_with_id(&db, &id).await.unwrap().unwrap();
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

    let deleted_schema = get_proof_schema_with_id(&db, &proof_schema_id)
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
        .delete_proof_schema(&Uuid::new_v4().into(), get_dummy_date())
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
        .get_proof_schema(&Uuid::new_v4().into(), &ProofSchemaRelations::default())
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
        id: Unchanged(proof_schema_id),
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
                    array: false,
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
        .times(1)
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
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
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
        organisation_id,
        "credential schema",
        "JWT",
        "NONE",
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
        })
        .collect();

    let claim_input = ProofInput {
        credential_schema_id,
        claims: &new_claim_schemas,
    };

    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    let proof_schema_id = insert_proof_schema_with_claims_to_database(
        &db,
        None,
        vec![&claim_input],
        organisation_id,
        "proof schema",
    )
    .await
    .unwrap();

    let result = repository
        .get_proof_schema(
            &proof_schema_id,
            &ProofSchemaRelations {
                organisation: Some(OrganisationRelations::default()),
                proof_inputs: Some(ProofInputSchemaRelations {
                    claim_schemas: Some(ProofSchemaClaimRelations::default()),
                    credential_schema: Some(CredentialSchemaRelations::default()),
                }),
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.id, proof_schema_id);

    assert!(result.organisation.is_some());
    assert_eq!(result.organisation.unwrap().id, organisation_id);

    assert!(result.input_schemas.is_some());
    let input_schema = result.input_schemas.unwrap()[0].to_owned();
    let claim_schemas = input_schema.claim_schemas.as_ref().unwrap().to_owned();
    assert_eq!(claim_schemas.len(), 2);
    assert_eq!(claim_schemas[0].schema.id, new_claim_schemas[0].id);
    assert_eq!(claim_schemas[1].schema.id, new_claim_schemas[1].id);

    assert!(input_schema.credential_schema.is_some());
    let credential_schema: &CredentialSchema = input_schema.credential_schema.as_ref().unwrap();
    assert_eq!(credential_schema.id, credential_schema_id);
}

#[tokio::test]
async fn test_get_proof_schema_with_input_proof_relations() {
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .returning(|ids, _| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                })
                .collect())
        });

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
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
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: id.to_string(),
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
        organisation_id,
        "credential schema",
        "JWT",
        "NONE",
    )
    .await
    .unwrap();

    let credential_schema_id2 = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema2",
        "JWT",
        "NONE",
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
        })
        .collect();

    let new_claim_schemas2: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: "test",
            required: i % 2 == 0,
            order: 2 + i as u32,
            datatype: "STRING",
            array: false,
        })
        .collect();

    let claim_input = ProofInput {
        credential_schema_id,
        claims: &new_claim_schemas,
    };

    let claim_input2 = ProofInput {
        credential_schema_id: credential_schema_id2,
        claims: &new_claim_schemas2,
    };

    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    insert_many_claims_schema_to_database(&db, &claim_input2)
        .await
        .unwrap();

    let proof_schema_id = insert_proof_schema_with_claims_to_database(
        &db,
        None,
        vec![&claim_input, &claim_input2],
        organisation_id,
        "proof schema",
    )
    .await
    .unwrap();

    let result = repository
        .get_proof_schema(
            &proof_schema_id,
            &ProofSchemaRelations {
                organisation: Some(OrganisationRelations::default()),
                proof_inputs: Some(ProofInputSchemaRelations {
                    claim_schemas: Some(ProofSchemaClaimRelations::default()),
                    credential_schema: Some(CredentialSchemaRelations::default()),
                }),
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.id, proof_schema_id);

    assert!(result.organisation.is_some());
    assert_eq!(result.organisation.unwrap().id, organisation_id);

    let proof_inputs: Vec<one_core::model::proof_schema::ProofInputSchema> =
        result.input_schemas.unwrap();
    assert_eq!(proof_inputs.len(), 2);
    assert_eq!(
        proof_inputs[0].credential_schema.as_ref().unwrap().id,
        credential_schema_id
    );
    assert_eq!(
        proof_inputs[1].credential_schema.as_ref().unwrap().id,
        credential_schema_id2
    );

    assert_eq!(proof_inputs[0].claim_schemas.as_ref().unwrap()[0].order, 0);
    assert_eq!(proof_inputs[1].claim_schemas.as_ref().unwrap()[0].order, 2);
    assert_eq!(
        proof_inputs[0].claim_schemas.as_ref().unwrap()[0].schema.id,
        new_claim_schemas[0].id
    );
    assert_eq!(
        proof_inputs[1].claim_schemas.as_ref().unwrap()[0].schema.id,
        new_claim_schemas2[0].id
    );
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
            organisation_id,
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
            organisation_id,
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
    let schema1_id = crate::entity::proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        name: Set("schema-1".to_string()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(None),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;

    let date_later = date_now + time::Duration::seconds(1);
    let schema2_id = crate::entity::proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_later),
        last_modified: Set(date_later),
        name: Set("schema-2".to_string()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(None),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;

    // default sorting - by created date descending
    let result = repository
        .get_proof_schema_list(GetProofSchemaQuery {
            page: 0,
            page_size: 2,
            exact: None,
            sort: None,
            sort_direction: None,
            name: None,
            organisation_id,
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
            organisation_id,
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
            organisation_id,
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
            organisation_id,
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
            organisation_id,
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
            organisation_id,
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
            organisation_id,
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
            organisation_id,
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
            organisation_id,
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
