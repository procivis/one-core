use std::ops::Add;
use std::sync::Arc;

use mockall::predicate::{always, eq};
use one_core::model::credential_schema::{CredentialSchemaType, LayoutType, WalletStorageTypeEnum};
use one_core::model::list_filter::{ComparisonType, ValueComparison};
use one_core::{
    model::{
        claim::{Claim, ClaimId, ClaimRelations},
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential::{
            Credential, CredentialRelations, CredentialRole, CredentialState, CredentialStateEnum,
            CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::{CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations},
        did::{Did, DidRelations},
        interaction::{Interaction, InteractionRelations},
        list_filter::ListFilterValue,
        list_query::ListPagination,
        organisation::{Organisation, OrganisationRelations},
    },
    repository::{
        claim_repository::MockClaimRepository, credential_repository::CredentialRepository,
        credential_schema_repository::MockCredentialSchemaRepository,
        did_repository::MockDidRepository, error::DataLayerError,
        interaction_repository::MockInteractionRepository, mock::key_repository::MockKeyRepository,
        revocation_list_repository::MockRevocationListRepository,
    },
    service::credential::dto::{CredentialFilterValue, GetCredentialQueryDTO},
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use shared_types::CredentialId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::CredentialProvider;
use crate::{entity::claim, test_utilities::*};

struct TestSetup {
    pub db: sea_orm::DatabaseConnection,
    pub credential_schema: CredentialSchema,
    pub did: Did,
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let credential_schema_id = Uuid::parse_str(
        &insert_credential_schema_to_database(
            &db,
            None,
            organisation_id,
            "credential schema",
            "JWT",
            "NONE",
        )
        .await
        .unwrap(),
    )
    .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: "key",
            required: i % 2 == 0,
            order: i as u32,
            datatype: "STRING",
        })
        .collect();

    let claim_input = ProofInput {
        credential_schema_id: credential_schema_id.to_string(),
        claims: &new_claim_schemas,
    };

    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    let credential_schema = CredentialSchema {
        id: credential_schema_id,
        deleted_at: None,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(
            new_claim_schemas
                .into_iter()
                .map(|schema| CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema.id,
                        key: schema.key.to_string(),
                        data_type: schema.datatype.to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                    },
                    required: true,
                })
                .collect(),
        ),
        organisation: Some(Organisation {
            id: organisation_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    };

    let did_id = &insert_did_key(
        &db,
        "issuer",
        Uuid::new_v4(),
        "did:key:123".parse().unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();

    let did = Did {
        id: *did_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_string(),
        organisation: Some(Organisation {
            id: organisation_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }),
        did: "did:key:123".parse().unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
        deactivated: false,
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

    let credential_id = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
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
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credential_id = Uuid::new_v4().into();
    let claims = vec![
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value1".to_string(),
            schema: Some(
                credential_schema.claim_schemas.as_ref().unwrap()[0]
                    .to_owned()
                    .schema,
            ),
        },
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value2".to_string(),
            schema: Some(
                credential_schema.claim_schemas.as_ref().unwrap()[1]
                    .to_owned()
                    .schema,
            ),
        },
    ];

    let result = provider
        .create_credential(Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            credential: vec![],
            transport: "transport".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: None,
            claims: Some(claims),
            issuer_did: Some(did),
            holder_did: None,
            schema: Some(credential_schema),
            interaction: None,
            revocation_list: None,
            key: None,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_id);

    assert_eq!(
        crate::entity::credential::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_create_credential_empty_claims() {
    let TestSetup {
        did,
        credential_schema,
        db,
        ..
    } = setup_empty().await;

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credential_id = Uuid::new_v4().into();
    let result = provider
        .create_credential(Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            credential: vec![],
            transport: "transport".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: None,
            claims: Some(vec![]),
            issuer_did: Some(did),
            holder_did: None,
            schema: Some(credential_schema),
            interaction: None,
            revocation_list: None,
            key: None,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_id);

    assert_eq!(
        crate::entity::credential::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
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
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let claims = vec![Claim {
        id: ClaimId::new_v4(),
        credential_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: "value1".to_string(),
        schema: Some(
            credential_schema.claim_schemas.as_ref().unwrap()[0]
                .to_owned()
                .schema,
        ),
    }];

    let result = provider
        .create_credential(Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            credential: vec![],
            transport: "transport".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: None,
            claims: Some(claims),
            issuer_did: Some(did),
            holder_did: None,
            schema: Some(credential_schema),
            interaction: None,
            revocation_list: None,
            key: None,
        })
        .await;

    assert!(matches!(result, Err(DataLayerError::AlreadyExists)));
}

#[tokio::test]
async fn test_delete_credential_success() {
    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let credential_id = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    provider.delete_credential(&credential_id).await.unwrap();

    let credential = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert!(credential.deleted_at.is_some());
}

#[tokio::test]
async fn test_delete_credential_failed_not_found() {
    let TestSetup { db, .. } = setup_empty().await;

    let credential_id = Uuid::new_v4().into();

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let result = provider.delete_credential(&credential_id).await;
    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated)));
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let _credential_one_id = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();
    let _credential_two_id = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let credential_three_id_should_not_be_returned = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        Some(OffsetDateTime::now_utc()),
    )
    .await
    .unwrap();

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            sorting: None,
            filtering: Some(
                CredentialFilterValue::OrganisationId(credential_schema.organisation.unwrap().id)
                    .condition(),
            ),
            include: None,
        })
        .await;
    assert!(credentials.is_ok());
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_pages);
    assert_eq!(2, credentials.total_items);
    assert_eq!(2, credentials.values.len());

    let forbidden_uuid = credential_three_id_should_not_be_returned;
    let forbidden_credential = credentials
        .values
        .iter()
        .find(|credential| credential.id == forbidden_uuid);
    assert!(forbidden_credential.is_none());
}

#[tokio::test]
async fn test_get_credential_list_success_verify_state_sorting() {
    let TestSetupWithCredential {
        credential_schema,
        db,
        credential_id,
        ..
    } = setup_with_credential().await;

    let later = OffsetDateTime::now_utc().add(Duration::seconds(1));
    insert_credential_state_to_database(
        &db,
        credential_id,
        CredentialState {
            created_date: later,
            state: CredentialStateEnum::Offered,
            suspend_end_date: None,
        },
    )
    .await
    .unwrap();

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            sorting: None,
            filtering: Some(
                CredentialFilterValue::OrganisationId(credential_schema.organisation.unwrap().id)
                    .condition(),
            ),
            include: None,
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_pages);
    assert_eq!(1, credentials.total_items);
    assert_eq!(1, credentials.values.len());

    let first = credentials.values.first().unwrap();
    let states = first.state.as_ref().unwrap();
    assert_eq!(1, states.len());
    assert_eq!(CredentialStateEnum::Offered, states.first().unwrap().state);
}

#[tokio::test]
async fn test_get_credential_list_success_filter_state() {
    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    let credential_id_first = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let credential_id_second = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let later = OffsetDateTime::now_utc().add(Duration::seconds(1));

    insert_credential_state_to_database(
        &db,
        credential_id_first,
        CredentialState {
            created_date: later,
            state: CredentialStateEnum::Offered,
            suspend_end_date: None,
        },
    )
    .await
    .unwrap();

    insert_credential_state_to_database(
        &db,
        credential_id_second,
        CredentialState {
            created_date: later,
            state: CredentialStateEnum::Revoked,
            suspend_end_date: None,
        },
    )
    .await
    .unwrap();

    let provider = CredentialProvider {
        db,
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::State(vec![CredentialStateEnum::Offered]).condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_items);
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::State(vec![CredentialStateEnum::Created]).condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(0, credentials.total_items);
    assert_eq!(0, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::State(vec![
                    CredentialStateEnum::Offered,
                    CredentialStateEnum::Revoked,
                ])
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(2, credentials.total_items);
    assert_eq!(2, credentials.values.len());
}

#[tokio::test]
async fn test_get_credential_list_success_filter_suspend_end_date() {
    let TestSetupWithCredential {
        db, credential_id, ..
    } = setup_with_credential().await;

    let later = OffsetDateTime::now_utc().add(Duration::seconds(1));
    let much_later = OffsetDateTime::now_utc().add(Duration::days(1));
    insert_credential_state_to_database(
        &db,
        credential_id,
        CredentialState {
            created_date: later,
            state: CredentialStateEnum::Suspended,
            suspend_end_date: Some(much_later),
        },
    )
    .await
    .unwrap();

    let provider = CredentialProvider {
        db,
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::SuspendEndDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: much_later,
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_items);
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::SuspendEndDate(ValueComparison {
                    comparison: ComparisonType::LessThan,
                    value: much_later,
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(0, credentials.total_items);
    assert_eq!(0, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::SuspendEndDate(ValueComparison {
                    comparison: ComparisonType::GreaterThan,
                    value: much_later,
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(0, credentials.total_items);
    assert_eq!(0, credentials.values.len());
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

    let credential_id = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let claims = vec![
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value1".to_string(),
            schema: Some(
                // order intentionally changed to check ordering of claims later
                credential_schema.claim_schemas.as_ref().unwrap()[1]
                    .to_owned()
                    .schema,
            ),
        },
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "value2".to_string(),
            schema: Some(
                credential_schema.claim_schemas.as_ref().unwrap()[0]
                    .to_owned()
                    .schema,
            ),
        },
    ];

    // claims need to be present for db consistence
    claim::Entity::insert_many(
        claims
            .iter()
            .map(|claim| claim::ActiveModel {
                id: Set(claim.id.into()),
                credential_id: Set(credential_id),
                claim_schema_id: Set(claim.schema.as_ref().unwrap().id),
                value: Set(claim.value.to_owned().into()),
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
        .returning(move |_, _| Ok(Some(did_clone.clone())));

    let credential_schema_clone = credential_schema.clone();
    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema_clone.clone())));

    let claims_clone = claims.clone();
    claim_repository
        .expect_get_claim_list()
        .withf(|ids, _| ids.len() == 2)
        .times(1)
        .returning(move |ids, _| {
            // order based on the requested ids
            Ok(ids
                .into_iter()
                .map(|id| {
                    claims_clone
                        .iter()
                        .find(|claim| claim.id == id)
                        .unwrap()
                        .to_owned()
                })
                .collect())
        });

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credential = provider
        .get_credential(
            &credential_id,
            &CredentialRelations {
                state: Some(CredentialStateRelations::default()),
                claims: Some(ClaimRelations {
                    schema: Some(ClaimSchemaRelations::default()),
                }),
                schema: Some(CredentialSchemaRelations {
                    claim_schemas: None,
                    organisation: Some(OrganisationRelations::default()),
                }),
                issuer_did: Some(DidRelations::default()),
                holder_did: Some(DidRelations::default()),
                interaction: Some(InteractionRelations::default()),
                revocation_list: None, // TODO: Add check for this
                key: None,
            },
        )
        .await;

    assert!(credential.is_ok());
    let credential = credential.unwrap().unwrap();
    assert_eq!(credential_id, credential.id);
    assert_eq!(credential_schema, credential.schema.unwrap());
    assert!(credential.interaction.is_none());
    let credential_claims = credential.claims.unwrap();
    assert_eq!(credential_claims.len(), 2);

    // claims must be ordered in the same way as in the credential_schema
    assert_eq!(credential_claims[0].id, claims[1].id);
    assert_eq!(credential_claims[1].id, claims[0].id);

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
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credential = provider
        .get_credential(&Uuid::new_v4().into(), &CredentialRelations::default())
        .await
        .unwrap();

    assert!(credential.is_none());
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

    let credential_id = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_get_interaction()
        .once()
        .returning(|id, _| {
            Ok(Some(Interaction {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                host: Some("https://host.co".parse().unwrap()),
                data: None,
            }))
        });

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(credential_schema_repository),
        claim_repository: Arc::from(claim_repository),
        did_repository: Arc::from(did_repository),
        interaction_repository: Arc::from(interaction_repository),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credential_before_update = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await;
    assert!(credential_before_update.is_ok());
    let credential_before_update = credential_before_update.unwrap().unwrap();
    assert_eq!(credential_id, credential_before_update.id);

    let token = vec![1, 2, 3];
    assert_ne!(token, credential_before_update.credential);

    let interaction_id =
        Uuid::parse_str(&insert_interaction(&db, "host", &[]).await.unwrap()).unwrap();

    assert!(provider
        .update_credential(UpdateCredentialRequest {
            id: credential_id.to_owned(),
            credential: Some(token.to_owned()),
            holder_did_id: None,
            issuer_did_id: None,
            state: None,
            interaction: Some(interaction_id),
            key: None,
            redirect_uri: None,
        })
        .await
        .is_ok());
    let credential_after_update = provider
        .get_credential(
            &credential_id,
            &CredentialRelations {
                interaction: Some(InteractionRelations::default()),
                ..Default::default()
            },
        )
        .await;
    assert!(credential_after_update.is_ok());
    let credential_after_update = credential_after_update.unwrap().unwrap();
    assert_eq!(token, credential_after_update.credential);
    assert_eq!(
        interaction_id,
        credential_after_update.interaction.unwrap().id
    );
}

#[tokio::test]
async fn test_get_credential_by_claim_id_success() {
    let TestSetup {
        credential_schema,
        did,
        db,
        ..
    } = setup_empty().await;

    // an unrelated credential
    insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let credential_id = insert_credential(
        &db,
        &credential_schema.id.to_string(),
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did.id,
        None,
    )
    .await
    .unwrap();

    let claim = Claim {
        id: ClaimId::new_v4(),
        credential_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: "value1".to_string(),
        schema: Some(
            credential_schema.claim_schemas.as_ref().unwrap()[0]
                .to_owned()
                .schema,
        ),
    };

    claim::ActiveModel {
        id: Set(claim.id.into()),
        credential_id: Set(credential_id),
        claim_schema_id: Set(claim.schema.as_ref().unwrap().id),
        value: Set(claim.value.as_bytes().to_owned()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
    }
    .insert(&db)
    .await
    .unwrap();

    let provider = CredentialProvider {
        db: db.clone(),
        credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
        claim_repository: Arc::from(MockClaimRepository::default()),
        did_repository: Arc::from(MockDidRepository::default()),
        interaction_repository: Arc::from(MockInteractionRepository::default()),
        revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
    };

    let credential = provider
        .get_credential_by_claim_id(&claim.id, &CredentialRelations::default())
        .await;

    assert!(credential.is_ok());
    let credential = credential.unwrap().unwrap();
    assert_eq!(credential_id, credential.id);
}
