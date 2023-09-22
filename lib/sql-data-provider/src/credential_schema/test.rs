use super::CredentialSchemaProvider;
use crate::test_utilities::*;
use one_core::{
    model::{
        claim_schema::{ClaimSchema, ClaimSchemaId, ClaimSchemaRelations},
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations,
            GetCredentialSchemaQuery,
        },
        organisation::{Organisation, OrganisationRelations},
    },
    repository::{
        credential_schema_repository::CredentialSchemaRepository,
        error::DataLayerError,
        mock::{
            claim_schema_repository::MockClaimSchemaRepository,
            organisation_repository::MockOrganisationRepository,
        },
    },
};
use sea_orm::{DatabaseConnection, EntityTrait};
use std::sync::Arc;
use uuid::Uuid;

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

    let organisation_id =
        Uuid::parse_str(&insert_organisation_to_database(&db, None).await.unwrap()).unwrap();

    TestSetup {
        organisation: Organisation {
            id: organisation_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        },
        repository: Box::new(CredentialSchemaProvider {
            db: db.clone(),
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

    let credential_schema_id = Uuid::parse_str(
        &insert_credential_schema_to_database(
            &db,
            None,
            &organisation.id.to_string(),
            "credential schema",
        )
        .await
        .unwrap(),
    )
    .unwrap();

    let new_claim_schemas: Vec<(Uuid, bool, u32, &str)> = (0..2)
        .map(|i| (Uuid::new_v4(), i % 2 == 0, i as u32, "STRING"))
        .collect();
    insert_many_claims_schema_to_database(
        &db,
        &credential_schema_id.to_string(),
        &new_claim_schemas,
    )
    .await
    .unwrap();

    TestSetupWithCredentialSchema {
        credential_schema: CredentialSchema {
            id: credential_schema_id,
            deleted_at: None,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "credential schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(
                new_claim_schemas
                    .into_iter()
                    .map(|(id, ..)| CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id,
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            key: "key1".to_string(),
                            data_type: "STRING".to_string(),
                        },
                        required: true,
                    })
                    .collect(),
            ),
            organisation: Some(organisation.clone()),
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

    let credential_schema_id = Uuid::new_v4();
    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: ClaimSchemaId::new_v4(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                key: "key1".to_string(),
                data_type: "STRING".to_string(),
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: ClaimSchemaId::new_v4(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                key: "key2".to_string(),
                data_type: "STRING".to_string(),
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
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(claim_schemas),
            organisation: Some(organisation),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_schema_id);

    assert_eq!(
        crate::entity::CredentialSchema::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::entity::CredentialSchemaClaimSchema::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        crate::entity::ClaimSchema::find()
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
        .get_credential_schema_list(GetCredentialSchemaQuery {
            page: 0,
            page_size: 5,
            sort: None,
            sort_direction: None,
            exact: None,
            name: None,
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(1, result.total_pages);
    assert_eq!(1, result.total_items);
    assert_eq!(1, result.values.len());
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
                })
                .collect())
        });

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| {
            Ok(Organisation {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            })
        });

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
    let result = result.unwrap();
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
async fn test_get_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let result = repository
        .get_credential_schema(&Uuid::new_v4(), &CredentialSchemaRelations::default())
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
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
        .delete_credential_schema(&credential_schema.id)
        .await;
    assert!(result.is_ok());

    let db_schemas = crate::entity::CredentialSchema::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(db_schemas.len(), 1);
    assert!(db_schemas[0].deleted_at.is_some());
}

#[tokio::test]
async fn test_delete_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let result = repository.delete_credential_schema(&Uuid::new_v4()).await;
    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
}
