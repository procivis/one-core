use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::error::DataLayerError;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection};
use shared_types::CredentialSchemaId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ClaimSchemaProvider;
use crate::entity;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn ClaimSchemaRepository>,
    pub credential_schema_id: CredentialSchemaId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        "JWT",
        None,
        None,
    )
    .await
    .unwrap();

    TestSetup {
        repository: Box::new(ClaimSchemaProvider {
            db: TransactionManagerImpl::new(db.clone()),
        }),
        db,
        credential_schema_id,
    }
}

#[tokio::test]
async fn test_get_claim_schema_list() {
    let TestSetup {
        repository,
        credential_schema_id,
        db,
    } = setup().await;

    let schemas = [
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "key1".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "key2".to_string(),
            data_type: "STRING".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            array: false,
            metadata: false,
        },
    ];

    for (index, claim) in schemas.iter().enumerate() {
        entity::claim_schema::ActiveModel {
            id: Set(claim.id),
            key: Set(claim.key.to_owned()),
            created_date: Set(claim.created_date),
            last_modified: Set(claim.last_modified),
            datatype: Set(claim.data_type.to_owned()),
            array: Set(claim.array),
            metadata: Set(claim.metadata),
            credential_schema_id: Set(credential_schema_id),
            required: Set(true),
            order: Set(index as _),
        }
        .insert(&db)
        .await
        .unwrap();
    }

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
            vec![schemas[0].id, Uuid::new_v4().into()],
            &ClaimSchemaRelations::default(),
        )
        .await;
    assert!(matches!(
        result,
        Err(DataLayerError::IncompleteClaimsSchemaList {
            expected: 2,
            got: 1
        })
    ));
}
