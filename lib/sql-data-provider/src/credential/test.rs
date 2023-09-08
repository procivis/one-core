use super::CredentialProvider;
use crate::{entity::claim, test_utilities::*};
use one_core::{
    model::{
        claim::{Claim, ClaimId},
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialId},
        credential_schema::CredentialSchema,
        did::Did,
        organisation::Organisation,
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
use sea_orm::{EntityTrait, Set};
use std::sync::Arc;
use uuid::Uuid;

struct TestSetup {
    pub provider: CredentialProvider,
    pub db: sea_orm::DatabaseConnection,
    pub credential_schema: CredentialSchema,
    pub did: Did,
}

#[derive(Default)]
struct Repositories {
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub claim_repository: MockClaimRepository,
    pub did_repository: MockDidRepository,
}

async fn setup_empty(repositories: Repositories) -> TestSetup {
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
        provider: CredentialProvider {
            db: db.clone(),
            credential_schema_repository: Arc::from(repositories.credential_schema_repository),
            claim_repository: Arc::from(repositories.claim_repository),
            did_repository: Arc::from(repositories.did_repository),
        },
        credential_schema,
        did,
        db,
    }
}

struct TestSetupWithCredential {
    pub provider: CredentialProvider,
    pub credential_schema: CredentialSchema,
    pub did: Did,
    pub credential_id: CredentialId,
}

async fn setup_with_credential(repositories: Repositories) -> TestSetupWithCredential {
    let TestSetup {
        provider,
        credential_schema,
        did,
        db,
        ..
    } = setup_empty(repositories).await;

    let credential_id = Uuid::parse_str(
        &insert_credential(&db, &credential_schema.id.to_string(), &did.id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    TestSetupWithCredential {
        provider,
        did,
        credential_id,
        credential_schema,
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
        provider,
        did,
        credential_schema,
        db,
        ..
    } = setup_empty(Repositories {
        claim_repository,
        ..Default::default()
    })
    .await;

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
        provider,
        did,
        credential_schema,
        credential_id,
        ..
    } = setup_with_credential(Repositories::default()).await;

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

// FIXME: cover other methods
