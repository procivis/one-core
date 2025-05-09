use std::collections::HashSet;
use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimId, ClaimRelations};
use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential::CredentialStateEnum;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::claim_schema_repository::{
    ClaimSchemaRepository, MockClaimSchemaRepository,
};
use one_core::repository::error::DataLayerError;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use shared_types::{ClaimSchemaId, CredentialId, CredentialSchemaId, IdentifierId};
use uuid::Uuid;

use super::ClaimProvider;
use crate::entity::claim_schema;
use crate::test_utilities::*;

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn ClaimRepository>,
    pub claim_schemas: Vec<ClaimSchema>,
    pub credential_id: CredentialId,
    pub identifier_id: IdentifierId,
    pub credential_schema_id: CredentialSchemaId,
}

async fn setup(claim_schema_repository: Arc<dyn ClaimSchemaRepository>) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let claim_schema_ids: Vec<ClaimSchemaId> = (0..4).map(|_| Uuid::new_v4().into()).collect();
    for id in &claim_schema_ids {
        claim_schema::ActiveModel {
            id: Set(*id),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            key: Set("TestKey".to_string()),
            datatype: Set("STRING".to_string()),
            array: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();
    }

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let credential_schema_id = &insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        "JWT",
        "NONE",
    )
    .await
    .unwrap();

    let did_id = insert_did_key(
        &db,
        "issuer",
        Uuid::new_v4(),
        "did:key:123".parse().unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();

    let identifier_id = insert_identifier(
        &db,
        "issuer",
        Uuid::new_v4(),
        Some(did_id),
        organisation_id,
        false,
    )
    .await
    .unwrap();

    let credential = insert_credential(
        &db,
        credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
    )
    .await
    .unwrap();

    TestSetup {
        repository: Box::new(ClaimProvider {
            db: db.clone(),
            claim_schema_repository,
        }),
        db,
        credential_id: credential.id,
        claim_schemas: claim_schema_ids
            .into_iter()
            .map(|id| ClaimSchema {
                id,
                key: format!("key {id}"),
                data_type: "STRING".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
            })
            .collect(),
        identifier_id,
        credential_schema_id: *credential_schema_id,
    }
}

fn get_claim_schema_repository_mock() -> Arc<dyn ClaimSchemaRepository> {
    Arc::from(MockClaimSchemaRepository::default())
}

#[tokio::test]
async fn test_create_claim_list_success() {
    let TestSetup {
        repository,
        claim_schemas,
        db,
        credential_id,
        ..
    } = setup(get_claim_schema_repository_mock()).await;

    let result = repository
        .create_claim_list(
            claim_schemas
                .into_iter()
                .map(|schema| Claim {
                    id: ClaimId::new_v4(),
                    credential_id,
                    value: "value".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    schema: Some(schema),
                })
                .collect(),
        )
        .await;
    assert!(result.is_ok());

    assert_eq!(
        crate::entity::claim::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        4
    );
}

#[tokio::test]
async fn test_delete_claims_for_credential() {
    let TestSetup {
        repository,
        claim_schemas,
        db,
        credential_id,
        ..
    } = setup(get_claim_schema_repository_mock()).await;

    repository
        .create_claim_list(
            claim_schemas
                .into_iter()
                .map(|schema| Claim {
                    id: ClaimId::new_v4(),
                    credential_id,
                    value: "value".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    schema: Some(schema),
                })
                .collect(),
        )
        .await
        .unwrap();

    repository
        .delete_claims_for_credential(credential_id)
        .await
        .unwrap();

    assert_eq!(
        crate::entity::claim::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn test_delete_claims_for_credentials() {
    let TestSetup {
        repository,
        claim_schemas,
        db,
        credential_id,
        credential_schema_id,
        identifier_id,
        ..
    } = setup(get_claim_schema_repository_mock()).await;

    let credential_id_2 = insert_credential(
        &db,
        &credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
    )
    .await
    .unwrap()
    .id;

    repository
        .create_claim_list(
            claim_schemas
                .iter()
                .map(|schema| Claim {
                    id: ClaimId::new_v4(),
                    credential_id,
                    value: "value".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    schema: Some(schema.clone()),
                })
                .collect(),
        )
        .await
        .unwrap();

    repository
        .create_claim_list(
            claim_schemas
                .into_iter()
                .map(|schema| Claim {
                    id: ClaimId::new_v4(),
                    credential_id: credential_id_2,
                    value: "value".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    schema: Some(schema),
                })
                .collect(),
        )
        .await
        .unwrap();

    repository
        .delete_claims_for_credentials(HashSet::from([credential_id, credential_id_2]))
        .await
        .unwrap();

    assert_eq!(
        crate::entity::claim::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn test_create_claim_list_missing_schema() {
    let TestSetup {
        repository,
        credential_id,
        ..
    } = setup(get_claim_schema_repository_mock()).await;

    let result = repository
        .create_claim_list(vec![Claim {
            id: ClaimId::new_v4(),
            credential_id,
            value: "value".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            path: String::default(),
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
        credential_id,
        ..
    } = setup(get_claim_schema_repository_mock()).await;

    let claims: Vec<Claim> = claim_schemas
        .iter()
        .map(|schema| Claim {
            id: ClaimId::new_v4(),
            credential_id,
            value: "value".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            path: schema.key.to_owned(),
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
    assert!(matches!(
        result,
        Err(DataLayerError::IncompleteClaimsList {
            expected: 2,
            got: 1
        })
    ));
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
                    array: false,
                })
                .collect())
        });

    let TestSetup {
        repository,
        claim_schemas,
        credential_id,
        ..
    } = setup(Arc::from(claim_schema_repository)).await;

    let claims: Vec<Claim> = claim_schemas
        .iter()
        .map(|schema| Claim {
            id: ClaimId::new_v4(),
            credential_id,
            value: "value".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            path: schema.key.to_owned(),
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
