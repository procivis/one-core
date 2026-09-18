use std::collections::HashSet;
use std::sync::Arc;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::common::SortDirection;
use one_core::model::credential_schema::{CredentialSchema, KeyStorageSecurity, WalletAttestation};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::list_filter::{ListFilterValue, StringMatch};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::proof_schema::{
    ProofInputClaimSchema, ProofInputSchema, ProofSchema, ProofSchemaListQuery,
    SortableProofSchemaColumn,
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
use one_core::service::proof_schema::dto::ProofSchemaFilterValue;
use sea_orm::{ActiveModelTrait, Set, Unchanged};
use shared_types::{OrganisationId, ProofSchemaId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ProofSchemaProvider;
use crate::entity::proof_schema;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

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
            db: TransactionManagerImpl::new(db.clone()),
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
            ecosystem: None,
            id: proof_schema_id,
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "test".to_string(),
            expire_duration: 0,
            organisation: dummy_organisation(Some(organisation_id)).into(),
            input_schemas: Default::default(),
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

    let credential_schema_id = Uuid::new_v4().into();
    let result = repository
        .create_proof_schema(ProofSchema {
            ecosystem: None,
            id: proof_schema_id,
            created_date: get_dummy_date(),
            imported_source_url: Some("CORE_URL".to_string()),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "test".to_string(),
            expire_duration: 0,
            organisation: dummy_organisation(Some(organisation_id)).into(),
            input_schemas: vec![ProofInputSchema {
                claim_schemas: vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "key".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    required: false,
                    order: 0,
                }]
                .into(),
                credential_schema: CredentialSchema {
                    expiration: None,
                    ecosystem: None,
                    batch_size: None,
                    allow_revocation: false,
                    id: credential_schema_id,
                    deleted_at: None,
                    wallet_attestation: WalletAttestation {
                        require_instance_attestation: false,
                        key_storage_security_level: Some(KeyStorageSecurity::Basic),
                        preferred_key_storage_attestation_lifetime: None,
                        preferred_instance_attestation_lifetime: None,
                    },
                    imported_source_url: "CORE_URL".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "schema".to_string(),
                    formats: vec![CredentialSchemaFormat {
                        id: Uuid::new_v4().into(),
                        created_date: one_core::clock::now_utc(),
                        last_modified: one_core::clock::now_utc(),
                        credential_schema_id,
                        format: "JWT".into(),
                        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
                        claim_mappings: Default::default(),
                    }]
                    .into(),
                    claim_schemas: Default::default(),
                    organisation: dummy_organisation(None).into(),
                    layout_properties: None,
                    allow_suspension: true,
                    transaction_code: None,
                    translations: Default::default(),
                    embedded_disclosure_policy: None,
                }
                .into(),
            }]
            .into(),
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
        false,
        Some(KeyStorageSecurity::Basic.into()),
    )
    .await
    .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
        .await
        .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: format!("test-{i}"),
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

    let id = Uuid::new_v4().into();
    let result = repository
        .create_proof_schema(ProofSchema {
            ecosystem: None,
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            imported_source_url: Some("CORE_URL".to_string()),
            deleted_at: None,
            name: "test".to_string(),
            expire_duration: 0,
            organisation: dummy_organisation(Some(organisation_id)).into(),
            input_schemas: vec![ProofInputSchema {
                claim_schemas: vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: new_claim_schemas[0].id,
                        key: "TestKey".to_string(),
                        data_type: new_claim_schemas[0].datatype.to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    required: false,
                    order: 0,
                }]
                .into(),
                credential_schema: CredentialSchema {
                    expiration: None,
                    ecosystem: None,
                    batch_size: None,
                    allow_revocation: false,
                    id: credential_schema_id,
                    deleted_at: None,
                    wallet_attestation: WalletAttestation {
                        require_instance_attestation: false,
                        key_storage_security_level: Some(KeyStorageSecurity::Basic),
                        preferred_key_storage_attestation_lifetime: None,
                        preferred_instance_attestation_lifetime: None,
                    },
                    imported_source_url: "CORE_URL".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "schema".to_string(),
                    formats: vec![CredentialSchemaFormat {
                        id: Uuid::new_v4().into(),
                        created_date: one_core::clock::now_utc(),
                        last_modified: one_core::clock::now_utc(),
                        credential_schema_id,
                        format: "JWT".into(),
                        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
                        claim_mappings: Default::default(),
                    }]
                    .into(),
                    claim_schemas: Default::default(),
                    organisation: dummy_organisation(None).into(),
                    layout_properties: None,
                    allow_suspension: true,
                    transaction_code: None,
                    translations: Default::default(),
                    embedded_disclosure_policy: None,
                }
                .into(),
            }]
            .into(),
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

    let result = repository.get_proof_schema(&Uuid::new_v4().into()).await;
    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
}

#[tokio::test]
async fn test_get_proof_schema() {
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

    let result = repository.get_proof_schema(&proof_schema_id).await.unwrap();

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

    let result = repository.get_proof_schema(&proof_schema_id).await.unwrap();

    assert_eq!(result.id, proof_schema_id);
    assert_eq!(result.deleted_at.unwrap(), delete_date);
}

#[tokio::test]
async fn test_get_proof_schema_with_relations() {
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .returning(|ids| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                })
                .collect())
        });

    let TestSetup {
        repository,
        organisation_id,
        db,
        ..
    } = setup_empty(
        Arc::from(claim_schema_repository),
        Arc::from(MockOrganisationRepository::default()),
        Arc::from(MockCredentialSchemaRepository::default()),
    )
    .await;

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        false,
        Some(KeyStorageSecurity::Basic.into()),
    )
    .await
    .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
        .await
        .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: format!("test-{i}"),
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

    let proof_schema_id = insert_proof_schema_with_claims_to_database(
        &db,
        None,
        vec![&claim_input],
        organisation_id,
        "proof schema",
    )
    .await
    .unwrap();

    let result = repository.get_proof_schema(&proof_schema_id).await.unwrap();

    assert_eq!(result.id, proof_schema_id);

    assert_eq!(result.organisation.id(), organisation_id);

    let input_schemas = result.input_schemas.as_ref().await.unwrap().to_owned();
    assert_eq!(input_schemas.len(), 1);
    let input_schema = input_schemas[0].to_owned();
    let claim_schemas = input_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    assert_eq!(claim_schemas.len(), 2);
    assert_eq!(claim_schemas[0].schema.id, new_claim_schemas[0].id);
    assert_eq!(claim_schemas[1].schema.id, new_claim_schemas[1].id);
    assert_eq!(input_schema.credential_schema.id(), credential_schema_id);
}

#[tokio::test]
async fn test_get_proof_schema_with_input_proof_relations() {
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .returning(|ids| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                })
                .collect())
        });

    let TestSetup {
        repository,
        organisation_id,
        db,
        ..
    } = setup_empty(
        Arc::from(claim_schema_repository),
        Arc::from(MockOrganisationRepository::default()),
        Arc::from(MockCredentialSchemaRepository::default()),
    )
    .await;

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        false,
        Some(KeyStorageSecurity::Basic.into()),
    )
    .await
    .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
        .await
        .unwrap();

    let credential_schema_id2 = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema2",
        false,
        Some(KeyStorageSecurity::Basic.into()),
    )
    .await
    .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id2, "JWT")
        .await
        .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: format!("test-{i}"),
            required: i % 2 == 0,
            order: i as u32,
            datatype: "STRING",
            array: false,
            metadata: false,
        })
        .collect();

    let new_claim_schemas2: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: format!("test-{i}"),
            required: i % 2 == 0,
            order: 2 + i as u32,
            datatype: "STRING",
            array: false,
            metadata: false,
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

    let result = repository.get_proof_schema(&proof_schema_id).await.unwrap();

    assert_eq!(result.id, proof_schema_id);

    assert_eq!(result.organisation.id(), organisation_id);

    let proof_inputs = result.input_schemas.as_ref().await.unwrap().to_owned();
    assert_eq!(proof_inputs.len(), 2);
    assert_eq!(proof_inputs[0].credential_schema.id(), credential_schema_id);
    assert_eq!(
        proof_inputs[1].credential_schema.id(),
        credential_schema_id2
    );

    assert_eq!(
        proof_inputs[0].claim_schemas.as_ref().await.unwrap()[0].order,
        0
    );
    assert_eq!(
        proof_inputs[1].claim_schemas.as_ref().await.unwrap()[0].order,
        2
    );
    assert_eq!(
        proof_inputs[0].claim_schemas.as_ref().await.unwrap()[0]
            .schema
            .id,
        new_claim_schemas[0].id
    );
    assert_eq!(
        proof_inputs[1].claim_schemas.as_ref().await.unwrap()[0]
            .schema
            .id,
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
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 0);
    assert_eq!(result.total_pages.unwrap(), 0);
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
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 0);
    assert_eq!(result.total_pages.unwrap(), 0);
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

    let date_now = one_core::clock::now_utc();
    let schema1_id = crate::entity::proof_schema::ActiveModel {
        ecosystem: Set(None),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        imported_source_url: Set(Some("CORE_URL".to_string())),
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
        ecosystem: Set(None),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_later),
        imported_source_url: Set(Some("CORE_URL".to_string())),
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
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 2);
    assert_eq!(result.total_pages.unwrap(), 1);
    assert_eq!(result.values.len(), 2);
    assert_eq!(result.values[0].id, schema2_id);

    // =========== SORTING
    // sort by name - default (ascending)
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableProofSchemaColumn::Name,
                direction: None,
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;
    assert_eq!(result.unwrap().values[0].id, schema1_id);

    // sort by name - descending
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableProofSchemaColumn::Name,
                direction: Some(SortDirection::Descending),
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;
    assert_eq!(result.unwrap().values[0].id, schema2_id);

    // sort by created-date - ascending
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableProofSchemaColumn::CreatedDate,
                direction: Some(SortDirection::Ascending),
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;
    assert_eq!(result.unwrap().values[0].id, schema1_id);

    // =========== FILTERING
    // filter by name - one result
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(
                ProofSchemaFilterValue::OrganisationId(organisation_id).condition()
                    & ProofSchemaFilterValue::Name(StringMatch::contains("schema-1".to_string())),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 1);
    assert_eq!(result.total_pages.unwrap(), 1);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema1_id);

    // filter by name - two results
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(
                ProofSchemaFilterValue::OrganisationId(organisation_id).condition()
                    & ProofSchemaFilterValue::Name(StringMatch::starts_with("schema".to_string())),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 2);
    assert_eq!(result.total_pages.unwrap(), 1);
    assert_eq!(result.values.len(), 2);

    // filter by name - no results
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(
                ProofSchemaFilterValue::OrganisationId(organisation_id).condition()
                    & ProofSchemaFilterValue::Name(StringMatch::contains("nothing".to_string())),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 0);
    assert_eq!(result.total_pages.unwrap(), 0);
    assert_eq!(result.values.len(), 0);

    // ====== PAGINATION
    // first page
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 2);
    assert_eq!(result.total_pages.unwrap(), 2);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema2_id);

    // second page
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            pagination: Some(ListPagination {
                page: 1,
                page_size: 1,
            }),
            filtering: Some(ProofSchemaFilterValue::OrganisationId(organisation_id).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items.unwrap(), 2);
    assert_eq!(result.total_pages.unwrap(), 2);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema1_id);
}

#[tokio::test]
async fn test_get_proof_schema_list_filter_formats() {
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

    let date_now = one_core::clock::now_utc();
    let cred_schema_jwt_id = crate::entity::credential_schema::ActiveModel {
        expiration: Set(None),
        ecosystem: Set(None),
        batch_size: Set(None),
        preferred_key_storage_attestation_lifetime: Set(None),
        preferred_instance_attestation_lifetime: Set(None),
        allow_revocation: Set(false),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        name: Set("jwt".to_string()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(None),
        key_storage_security: Set(None),
        layout_properties: Set(None),
        imported_source_url: Set("URL".to_string()),
        allow_suspension: Set(false),
        requires_wallet_instance_attestation: Set(false),
        transaction_code_type: Set(None),
        transaction_code_length: Set(None),
        transaction_code_description: Set(None),
        embedded_disclosure_policy: Set(None),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;

    crate::entity::credential_schema_format::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        credential_schema_id: Set(cred_schema_jwt_id),
        format: Set("JWT".into()),
        ecosystem_schema_id: Set("JWT".to_string()),
    }
    .insert(&db)
    .await
    .unwrap();

    let cred_schema_mdoc_id = crate::entity::credential_schema::ActiveModel {
        expiration: Set(None),
        ecosystem: Set(None),
        batch_size: Set(None),
        preferred_key_storage_attestation_lifetime: Set(None),
        preferred_instance_attestation_lifetime: Set(None),
        allow_revocation: Set(false),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        name: Set("mdoc".to_string()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(None),
        key_storage_security: Set(None),
        layout_properties: Set(None),
        imported_source_url: Set("URL".to_string()),
        allow_suspension: Set(false),
        requires_wallet_instance_attestation: Set(false),
        transaction_code_type: Set(None),
        transaction_code_length: Set(None),
        transaction_code_description: Set(None),
        embedded_disclosure_policy: Set(None),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;

    crate::entity::credential_schema_format::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        credential_schema_id: Set(cred_schema_mdoc_id),
        format: Set("MDOC".into()),
        ecosystem_schema_id: Set("MDOC".to_string()),
    }
    .insert(&db)
    .await
    .unwrap();

    let schema_jwt_only_id = crate::entity::proof_schema::ActiveModel {
        ecosystem: Set(None),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        imported_source_url: Set(Some("CORE_URL".to_string())),
        name: Set("proof-jwt-only".to_string()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(None),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;

    crate::entity::proof_input_schema::ActiveModel {
        id: Set(1),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        order: Set(1),
        credential_schema: Set(cred_schema_jwt_id),
        proof_schema: Set(schema_jwt_only_id),
    }
    .insert(&db)
    .await
    .unwrap();

    let schema_mdoc_only_id = crate::entity::proof_schema::ActiveModel {
        ecosystem: Set(None),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        imported_source_url: Set(Some("CORE_URL".to_string())),
        name: Set("proof-mdoc-only".to_string()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(None),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;

    crate::entity::proof_input_schema::ActiveModel {
        id: Set(2),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        order: Set(1),
        credential_schema: Set(cred_schema_mdoc_id),
        proof_schema: Set(schema_mdoc_only_id),
    }
    .insert(&db)
    .await
    .unwrap();

    let schema_mdoc_and_jwt_id = crate::entity::proof_schema::ActiveModel {
        ecosystem: Set(None),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        imported_source_url: Set(Some("CORE_URL".to_string())),
        name: Set("proof-mdoc-and-jwt".to_string()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(None),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;

    crate::entity::proof_input_schema::ActiveModel {
        id: Set(3),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        order: Set(1),
        credential_schema: Set(cred_schema_mdoc_id),
        proof_schema: Set(schema_mdoc_and_jwt_id),
    }
    .insert(&db)
    .await
    .unwrap();

    crate::entity::proof_input_schema::ActiveModel {
        id: Set(4),
        created_date: Set(date_now),
        last_modified: Set(date_now),
        order: Set(2),
        credential_schema: Set(cred_schema_jwt_id),
        proof_schema: Set(schema_mdoc_and_jwt_id),
    }
    .insert(&db)
    .await
    .unwrap();

    // JWT only
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            filtering: Some(ProofSchemaFilterValue::Formats(vec!["JWT".to_string()]).condition()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema_jwt_only_id);

    // MDOC only
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            filtering: Some(ProofSchemaFilterValue::Formats(vec!["MDOC".to_string()]).condition()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, schema_mdoc_only_id);

    // MDOC or JWT
    let result = repository
        .get_proof_schema_list(ProofSchemaListQuery {
            filtering: Some(
                ProofSchemaFilterValue::Formats(vec!["MDOC".to_string(), "JWT".to_string()])
                    .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(result.values.len(), 3);
    let ids: HashSet<_> = result.values.iter().map(|val| val.id).collect();
    assert!(ids.contains(&schema_mdoc_only_id));
    assert!(ids.contains(&schema_jwt_only_id));
    assert!(ids.contains(&schema_mdoc_and_jwt_id));
}
