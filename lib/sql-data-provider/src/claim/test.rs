use super::ClaimProvider;
use crate::{entity::claim_schema, test_utilities::*};
use one_core::{
    model::{
        claim::{Claim, ClaimId, ClaimRelations},
        claim_schema::{ClaimSchema, ClaimSchemaId, ClaimSchemaRelations},
    },
    repository::{
        claim_repository::ClaimRepository, claim_schema_repository::ClaimSchemaRepository,
        error::DataLayerError, mock::claim_schema_repository::MockClaimSchemaRepository,
    },
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use std::sync::Arc;

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn ClaimRepository>,
    pub claim_schemas: Vec<ClaimSchema>,
}

async fn setup(claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let claim_schema_ids: Vec<ClaimSchemaId> = (0..4).map(|_| ClaimSchemaId::new_v4()).collect();
    for id in &claim_schema_ids {
        claim_schema::ActiveModel {
            id: Set(id.to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            key: Set("TestKey".to_string()),
            datatype: Set("STRING".to_string()),
        }
        .insert(&db)
        .await
        .unwrap();
    }

    TestSetup {
        repository: Box::new(ClaimProvider {
            db: db.clone(),
            claim_schema_repository,
        }),
        db,
        claim_schemas: claim_schema_ids
            .into_iter()
            .map(|id| ClaimSchema {
                id,
                key: format!("key {id}"),
                data_type: "STRING".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            })
            .collect(),
    }
}

fn get_claim_schema_repository_mock() -> Arc<dyn ClaimSchemaRepository + Send + Sync> {
    Arc::from(MockClaimSchemaRepository::default())
}

#[tokio::test]
async fn test_create_claim_list_success() {
    let TestSetup {
        repository,
        claim_schemas,
        db,
        ..
    } = setup(get_claim_schema_repository_mock()).await;

    let result = repository
        .create_claim_list(
            claim_schemas
                .into_iter()
                .map(|schema| Claim {
                    id: ClaimId::new_v4(),
                    value: "value".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    schema: Some(schema),
                })
                .collect(),
        )
        .await;
    assert!(result.is_ok());

    assert_eq!(
        crate::entity::Claim::find().all(&db).await.unwrap().len(),
        4
    );
}

#[tokio::test]
async fn test_create_claim_list_missing_schema() {
    let TestSetup { repository, .. } = setup(get_claim_schema_repository_mock()).await;

    let result = repository
        .create_claim_list(vec![Claim {
            id: ClaimId::new_v4(),
            value: "value".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            schema: None,
        }])
        .await;
    assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
}

#[tokio::test]
async fn test_get_claim_list() {
    let TestSetup {
        repository,
        claim_schemas,
        ..
    } = setup(get_claim_schema_repository_mock()).await;

    let claims: Vec<Claim> = claim_schemas
        .iter()
        .map(|schema| Claim {
            id: ClaimId::new_v4(),
            value: "value".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            schema: Some(schema.to_owned()),
        })
        .collect();
    repository.create_claim_list(claims.clone()).await.unwrap();

    // single item
    let result = repository
        .get_claim_list(vec![claims[0].id], &ClaimRelations::default())
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, claims[0].id);

    // two items - different order
    let result = repository
        .get_claim_list(vec![claims[3].id, claims[1].id], &ClaimRelations::default())
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].id, claims[3].id);
    assert_eq!(result[1].id, claims[1].id);

    // one item missing
    let result = repository
        .get_claim_list(
            vec![claims[0].id, ClaimId::new_v4()],
            &ClaimRelations::default(),
        )
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
}

#[tokio::test]
async fn test_get_claim_list_with_relation() {
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
                    key: format!("key {id}"),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                })
                .collect())
        });

    let TestSetup {
        repository,
        claim_schemas,
        ..
    } = setup(Arc::from(claim_schema_repository)).await;

    let claims: Vec<Claim> = claim_schemas
        .iter()
        .map(|schema| Claim {
            id: ClaimId::new_v4(),
            value: "value".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            schema: Some(schema.to_owned()),
        })
        .collect();
    repository.create_claim_list(claims.clone()).await.unwrap();

    let result = repository
        .get_claim_list(
            vec![claims[2].id, claims[1].id],
            &ClaimRelations {
                schema: Some(ClaimSchemaRelations::default()),
            },
        )
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].id, claims[2].id);
    assert_eq!(result[1].id, claims[1].id);

    assert_eq!(result[1].value, claims[1].value);

    assert!(result[1].schema.is_some());
    let schema1 = result[1].schema.as_ref().unwrap();
    assert_eq!(schema1.id, claim_schemas[1].id);
}