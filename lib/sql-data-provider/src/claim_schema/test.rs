use super::ClaimSchemaProvider;
use crate::test_utilities::*;
use one_core::{
    model::claim_schema::{ClaimSchema, ClaimSchemaId, ClaimSchemaRelations},
    repository::{claim_schema_repository::ClaimSchemaRepository, error::DataLayerError},
};
use sea_orm::{DatabaseConnection, EntityTrait};

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn ClaimSchemaRepository>,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    TestSetup {
        repository: Box::new(ClaimSchemaProvider { db: db.clone() }),
        db,
    }
}

#[tokio::test]
async fn test_create_claim_schema_list() {
    let TestSetup { repository, db, .. } = setup().await;

    let result = repository
        .create_claim_schema_list(vec![ClaimSchema {
            id: ClaimSchemaId::new_v4(),
            key: "key".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }])
        .await;
    assert!(result.is_ok());

    assert_eq!(
        crate::entity::ClaimSchema::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_get_claim_schema_list() {
    let TestSetup { repository, .. } = setup().await;

    let schemas = vec![
        ClaimSchema {
            id: ClaimSchemaId::new_v4(),
            key: "key1".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        },
        ClaimSchema {
            id: ClaimSchemaId::new_v4(),
            key: "key2".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        },
    ];
    repository
        .create_claim_schema_list(schemas.clone())
        .await
        .unwrap();

    // single item
    let result = repository
        .get_claim_schema_list(vec![schemas[0].id], &ClaimSchemaRelations::default())
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, schemas[0].id);

    // both items - same order
    let result = repository
        .get_claim_schema_list(
            vec![schemas[0].id, schemas[1].id],
            &ClaimSchemaRelations::default(),
        )
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].id, schemas[0].id);
    assert_eq!(result[1].id, schemas[1].id);

    // both items - different order
    let result = repository
        .get_claim_schema_list(
            vec![schemas[1].id, schemas[0].id],
            &ClaimSchemaRelations::default(),
        )
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].id, schemas[1].id);
    assert_eq!(result[1].id, schemas[0].id);

    // one item missing
    let result = repository
        .get_claim_schema_list(
            vec![schemas[0].id, ClaimSchemaId::new_v4()],
            &ClaimSchemaRelations::default(),
        )
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
}