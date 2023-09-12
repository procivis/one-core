use super::CredentialProvider;
use crate::{entity::claim, test_utilities::*};
use mockall::predicate::{always, eq};
use one_core::{
    model::{
        claim::{Claim, ClaimId, ClaimRelations},
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialStateEnum,
            CredentialStateRelations, GetCredentialQuery, UpdateCredentialRequest,
        },
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        did::{Did, DidRelations},
        organisation::{Organisation, OrganisationRelations},
    },
    repository::{
        credential_repository::CredentialRepository,
        error::DataLayerError,
        mock::{
            claim_repository::MockClaimRepository,
            credential_schema_repository::MockCredentialSchemaRepository,
            did_repository::MockDidRepository,
        },
    },
};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use std::sync::Arc;
use uuid::Uuid;

struct TestSetup {
    pub db: sea_orm::DatabaseConnection,
    pub credential_schema: CredentialSchema,
    pub did: Did,
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id =
        Uuid::parse_str(&insert_organisation_to_database(&db, None).await.unwrap()).unwrap();

    let credential_schema_id = Uuid::parse_str(
        &insert_credential_schema_to_database(
            &db,
            None,
            &organisation_id.to_string(),
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

    let credential_schema = CredentialSchema {
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
                .map(|schema| ClaimSchema {
                    id: schema.0,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                })
                .collect(),
        ),
        organisation: Some(Organisation {
            id: organisation_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }),
    };

    let did_id = Uuid::parse_str(
        &insert_did(&db, "issuer", "did:key:123", &organisation_id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();
    let did = Did {
        id: did_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_string(),
        organisation_id,
        did: "did:key:123".to_string(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".to_string(),
    };

    TestSetup {
        credential_schema,
        did,
        db,
    }
}

struct TestSetupWithCredential {
    pub credential_schema: CredentialSchema,
    pub did: Did,
    pub credential_id: CredentialId,
    pub db: DatabaseConnection,
}

async fn setup_with_credential() -> TestSetupWithCredential {
    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let credential_id = Uuid::parse_str(
        &insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    TestSetupWithCredential {
        did,
        credential_id,
        credential_schema,
        db,
    }
}

#[tokio::test]
async fn test_create_credential_success() {
    let mut claim_repository = MockClaimRepository::default();
    claim_repository
        .expect_create_claim_list()
        .times(1)
        .withf(|claims| claims.len() == 2)
        .returning(|_| Ok(()));

    let TestSetup {
        did,
        credential_schema,
        db,
        ..
    } = setup_empty().await;

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(MockDidRepository::default()),
    };

    let credential_id = Uuid::new_v4();
    let claims = vec![
        Claim {
            id: ClaimId::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value1".to_string(),
            schema: Some(credential_schema.claim_schemas.as_ref().unwrap()[0].to_owned()),
        },
        Claim {
            id: ClaimId::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value2".to_string(),
            schema: Some(credential_schema.claim_schemas.as_ref().unwrap()[1].to_owned()),
        },
    ];

    // claims need to be present for db consistence
    claim::Entity::insert_many(
        claims
            .iter()
            .map(|claim| claim::ActiveModel {
                id: Set(claim.id.to_string()),
                claim_schema_id: Set(claim.schema.as_ref().unwrap().id.to_string()),
                value: Set(claim.value.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
            })
            .collect::<Vec<claim::ActiveModel>>(),
    )
    .exec(&db)
    .await
    .unwrap();

    let result = provider
        .create_credential(Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            credential: vec![],
            transport: "transport".to_string(),
            state: None,
            claims: Some(claims),
            issuer_did: Some(did),
            holder_did: None,
            schema: Some(credential_schema),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_id);

    assert_eq!(
        crate::entity::Credential::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::entity::CredentialClaim::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn test_create_credential_already_exists() {
    let TestSetupWithCredential {
        did,
        credential_schema,
        credential_id,
        db,
    } = setup_with_credential().await;

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
    };

    let claims = vec![Claim {
        id: ClaimId::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: "value1".to_string(),
        schema: Some(credential_schema.claim_schemas.as_ref().unwrap()[0].to_owned()),
    }];

    let result = provider
        .create_credential(Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            credential: vec![],
            transport: "transport".to_string(),
            state: None,
            claims: Some(claims),
            issuer_did: Some(did),
            holder_did: None,
            schema: Some(credential_schema),
        })
        .await;

    assert!(matches!(result, Err(DataLayerError::AlreadyExists)));
}

#[tokio::test]
async fn test_get_all_credential_list_success() {
    let claim_repository = MockClaimRepository::default();
    let mut did_repository = MockDidRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let did_clone = did.clone();
    did_repository
        .expect_get_did()
        .times(2)
        .with(eq(did_clone.id.to_owned()), always())
        .returning(move |_, _| Ok(did_clone.clone()));

    let credential_one_id =
        insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap();
    let credential_two_id =
        insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap();

    let credential_schema_clone = credential_schema.clone();
    credential_schema_repository
        .expect_get_credential_schema()
        .times(2)
        .returning(move |_, _| Ok(credential_schema_clone.clone()));

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
    };

    let credentials = provider.get_all_credential_list().await;
    assert!(credentials.is_ok());
    let credentials = credentials.unwrap();
    assert_eq!(2, credentials.len());
    assert_eq!(credential_one_id, credentials[0].id.to_string());
    assert_eq!(
        CredentialStateEnum::Created,
        credentials[0].state.as_ref().unwrap()[0].state
    );
    assert_eq!(credential_two_id, credentials[1].id.to_string());
    assert_eq!(
        CredentialStateEnum::Created,
        credentials[1].state.as_ref().unwrap()[0].state
    );
}

#[tokio::test]
async fn test_get_all_credential_failure_credential_schema_not_found() {
    let claim_repository = MockClaimRepository::default();
    let mut did_repository = MockDidRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let did_clone = did.clone();
    did_repository
        .expect_get_did()
        .times(1)
        .with(eq(did_clone.id.to_owned()), always())
        .returning(move |_, _| Ok(did_clone.clone()));

    let _credential_one_id =
        insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap();

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Err(DataLayerError::RecordNotFound));

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
    };

    let credentials = provider.get_all_credential_list().await;
    assert!(credentials.is_err_and(|e| matches!(e, DataLayerError::RecordNotFound)));
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let claim_repository = MockClaimRepository::default();
    let mut did_repository = MockDidRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let did_clone = did.clone();
    did_repository
        .expect_get_did()
        .times(2)
        .with(eq(did_clone.id.to_owned()), always())
        .returning(move |_, _| Ok(did_clone.clone()));

    let _credential_one_id =
        insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap();
    let _credential_two_id =
        insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap();

    let credential_schema_clone = credential_schema.clone();
    credential_schema_repository
        .expect_get_credential_schema()
        .times(2)
        .returning(move |_, _| Ok(credential_schema_clone.clone()));

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
    };

    let credentials = provider
        .get_credential_list(GetCredentialQuery {
            page: 0,
            page_size: 5,
            sort: None,
            sort_direction: None,
            name: None,
            organisation_id: credential_schema
                .organisation
                .as_ref()
                .unwrap()
                .id
                .to_string(),
        })
        .await;
    assert!(credentials.is_ok());
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_pages);
    assert_eq!(2, credentials.total_items);
    assert_eq!(2, credentials.values.len());
}

#[tokio::test]
async fn test_get_credential_success() {
    let mut claim_repository = MockClaimRepository::default();
    let mut did_repository = MockDidRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let credential_id = Uuid::parse_str(
        &insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    let claims = vec![
        Claim {
            id: ClaimId::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value1".to_string(),
            schema: Some(credential_schema.claim_schemas.as_ref().unwrap()[0].to_owned()),
        },
        Claim {
            id: ClaimId::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value2".to_string(),
            schema: Some(credential_schema.claim_schemas.as_ref().unwrap()[1].to_owned()),
        },
    ];

    // claims need to be present for db consistence
    claim::Entity::insert_many(
        claims
            .iter()
            .map(|claim| claim::ActiveModel {
                id: Set(claim.id.to_string()),
                claim_schema_id: Set(claim.schema.as_ref().unwrap().id.to_string()),
                value: Set(claim.value.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
            })
            .collect::<Vec<claim::ActiveModel>>(),
    )
    .exec(&db)
    .await
    .unwrap();

    let did_clone = did.clone();
    did_repository
        .expect_get_did()
        .times(1)
        .with(eq(did_clone.id.to_owned()), always())
        .returning(move |_, _| Ok(did_clone.clone()));

    let credential_schema_clone = credential_schema.clone();
    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(credential_schema_clone.clone()));

    claim_repository
        .expect_get_claim_list()
        .times(1)
        .returning(move |_, _| Ok(claims.clone()));

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
    };

    let credential = provider
        .get_credential(
            &credential_id,
            &CredentialRelations {
                state: Some(CredentialStateRelations {}),
                claims: Some(ClaimRelations {
                    schema: Some(ClaimSchemaRelations {}),
                }),
                schema: Some(CredentialSchemaRelations {
                    claim_schema: None,
                    organisation: Some(OrganisationRelations {}),
                }),
                issuer_did: Some(DidRelations {}),
                holder_did: Some(DidRelations {}),
            },
        )
        .await;

    assert!(credential.is_ok());
    let credential = credential.unwrap();
    assert_eq!(credential_id, credential.id);
    assert_eq!(credential_schema, credential.schema.unwrap());

    let empty_relations_mean_no_other_repository_calls = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await;
    assert!(empty_relations_mean_no_other_repository_calls.is_ok());
}

#[tokio::test]
async fn test_get_credential_fail_not_found() {
    let claim_repository = MockClaimRepository::default();
    let did_repository = MockDidRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();

    let TestSetup { db, .. } = setup_empty().await;

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
    };

    let credential = provider
        .get_credential(&Uuid::new_v4(), &CredentialRelations::default())
        .await;

    assert!(credential.is_err_and(|e| matches!(e, DataLayerError::RecordNotFound)));
}

#[tokio::test]
async fn test_update_credential_success() {
    let claim_repository = MockClaimRepository::default();
    let did_repository = MockDidRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();

    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let credential_id = Uuid::parse_str(
        &insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
    };

    let credential_before_update = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await;
    assert!(credential_before_update.is_ok());
    let credential_before_update = credential_before_update.unwrap();
    assert_eq!(credential_id, credential_before_update.id);

    let token = vec![1, 2, 3];
    assert_ne!(token, credential_before_update.credential);

    assert!(provider
        .update_credential(UpdateCredentialRequest {
            id: credential_id.to_owned(),
            credential: Some(token.to_owned()),
            holder_did_id: None,
            state: None,
        })
        .await
        .is_ok());
    let credential_after_update = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await;
    assert!(credential_after_update.is_ok());
    let credential_after_update = credential_after_update.unwrap();
    assert_eq!(token, credential_after_update.credential);
}
