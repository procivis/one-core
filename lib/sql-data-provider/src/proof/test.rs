use super::ProofProvider;
use crate::{
    entity::{
        claim,
        proof_state::{self, ProofRequestState},
    },
    list_query::from_pagination,
    test_utilities::*,
};
use one_core::{
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaId,
        did::{Did, DidId, DidRelations, DidType},
        organisation::OrganisationId,
        proof::{Proof, ProofId, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
        proof_schema::{ProofSchema, ProofSchemaId, ProofSchemaRelations},
    },
    repository::{
        claim_repository::ClaimRepository,
        did_repository::DidRepository,
        error::DataLayerError,
        mock::{
            claim_repository::MockClaimRepository, did_repository::MockDidRepository,
            proof_schema_repository::MockProofSchemaRepository,
        },
        proof_repository::ProofRepository,
        proof_schema_repository::ProofSchemaRepository,
    },
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, QueryOrder, Set};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn ProofRepository>,
    pub organisation_id: OrganisationId,
    pub proof_schema_id: ProofSchemaId,
    pub did_id: DidId,
    pub claim_schema_ids: Vec<ClaimSchemaId>,
}

async fn setup(
    proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = Uuid::new_v4();
    insert_organisation_to_database(&db, Some(organisation_id))
        .await
        .unwrap();

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

    let new_claim_schemas: Vec<(Uuid, bool, u32, &str)> = (0..4)
        .map(|i| (Uuid::new_v4(), i % 2 == 0, i, "STRING"))
        .collect();
    insert_many_claims_schema_to_database(
        &db,
        &credential_schema_id.to_string(),
        &new_claim_schemas,
    )
    .await
    .unwrap();

    let proof_schema_id = Uuid::parse_str(
        &insert_proof_schema_with_claims_to_database(
            &db,
            None,
            &new_claim_schemas,
            &organisation_id.to_string(),
            "proof schema",
        )
        .await
        .unwrap(),
    )
    .unwrap();

    let did_id = Uuid::parse_str(
        &insert_did(&db, "verifier", "did:key:123", &organisation_id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    TestSetup {
        repository: Box::new(ProofProvider {
            db: db.clone(),
            proof_schema_repository,
            claim_repository,
            did_repository,
        }),
        db,
        organisation_id,
        proof_schema_id,
        did_id,
        claim_schema_ids: new_claim_schemas.into_iter().map(|item| item.0).collect(),
    }
}

struct TestSetupWithProof {
    pub repository: Box<dyn ProofRepository>,
    pub organisation_id: OrganisationId,
    pub proof_schema_id: ProofSchemaId,
    pub did_id: DidId,
    pub proof_id: ProofId,
    pub db: DatabaseConnection,
    pub claim_schema_ids: Vec<ClaimSchemaId>,
}

async fn setup_with_proof(
    proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
) -> TestSetupWithProof {
    let TestSetup {
        repository,
        db,
        proof_schema_id,
        did_id,
        organisation_id,
        claim_schema_ids,
        ..
    } = setup(proof_schema_repository, claim_repository, did_repository).await;

    let proof_id = Uuid::parse_str(
        &insert_proof_request_to_database(
            &db,
            &did_id.to_string(),
            None,
            &proof_schema_id.to_string(),
        )
        .await
        .unwrap(),
    )
    .unwrap();

    insert_proof_state_to_database(
        &db,
        &proof_id.to_string(),
        crate::entity::proof_state::ProofRequestState::Created,
    )
    .await
    .unwrap();

    TestSetupWithProof {
        repository,
        organisation_id,
        proof_schema_id,
        did_id,
        proof_id,
        db,
        claim_schema_ids,
    }
}

fn get_proof_schema_repository_mock() -> Arc<dyn ProofSchemaRepository + Send + Sync> {
    Arc::from(MockProofSchemaRepository::default())
}

fn get_claim_repository_mock() -> Arc<dyn ClaimRepository + Send + Sync> {
    Arc::from(MockClaimRepository::default())
}

fn get_did_repository_mock() -> Arc<dyn DidRepository + Send + Sync> {
    Arc::from(MockDidRepository::default())
}

#[tokio::test]
async fn test_create_proof_success() {
    let TestSetup {
        repository,
        db,
        proof_schema_id,
        did_id,
        organisation_id,
        ..
    } = setup(
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_did_repository_mock(),
    )
    .await;

    let proof_id = Uuid::new_v4();
    let proof = Proof {
        id: proof_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        issuance_date: get_dummy_date(),
        transport: "test".to_string(),
        state: Some(vec![ProofState {
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            state: ProofStateEnum::Created,
        }]),
        schema: Some(ProofSchema {
            id: proof_schema_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "proof schema".to_string(),
            expire_duration: 0,
            claim_schemas: None,
            organisation: None,
        }),
        claims: None,
        verifier_did: Some(Did {
            id: did_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "verifier".to_string(),
            organisation_id,
            did: "did:key:123".to_string(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
        }),
        holder_did: None,
    };

    let result = repository.create_proof(proof).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), proof_id);

    assert_eq!(
        crate::entity::Proof::find().all(&db).await.unwrap().len(),
        1
    );
    assert_eq!(
        crate::entity::ProofState::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_get_proof_list() {
    let TestSetupWithProof {
        repository,
        organisation_id,
        proof_id,
        ..
    } = setup_with_proof(
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_did_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof_list(from_pagination(0, 1, organisation_id.to_string()))
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 1);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 1);

    let proof = &result.values[0];
    assert_eq!(proof.id, proof_id);
}

#[tokio::test]
async fn test_get_proof_missing() {
    let TestSetup { repository, .. } = setup(
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_did_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof(&Uuid::new_v4(), &ProofRelations::default())
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
}

#[tokio::test]
async fn test_get_proof_no_relations() {
    let TestSetupWithProof {
        repository,
        proof_id,
        ..
    } = setup_with_proof(
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_did_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof(&proof_id, &ProofRelations::default())
        .await;
    assert!(result.is_ok());
    let proof = result.unwrap();
    assert_eq!(proof.id, proof_id);
}

#[tokio::test]
async fn test_get_proof_with_relations() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|id, _| {
            Ok(ProofSchema {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "proof schema".to_string(),
                expire_duration: 0,
                claim_schemas: None,
                organisation: None,
            })
        });

    let mut did_repository = MockDidRepository::default();
    did_repository.expect_get_did().times(1).returning(|id, _| {
        Ok(Did {
            id: id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "verifier".to_string(),
            organisation_id: Uuid::new_v4(),
            did: "did:key:123".to_string(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
        })
    });

    let TestSetupWithProof {
        repository,
        proof_id,
        proof_schema_id,
        did_id,
        ..
    } = setup_with_proof(
        Arc::from(proof_schema_repository),
        get_claim_repository_mock(),
        Arc::from(did_repository),
    )
    .await;

    let result = repository
        .get_proof(
            &proof_id,
            &ProofRelations {
                state: Some(ProofStateRelations::default()),
                claims: Some(ClaimRelations::default()),
                schema: Some(ProofSchemaRelations::default()),
                verifier_did: Some(DidRelations::default()),
                holder_did: Some(DidRelations::default()),
            },
        )
        .await;
    assert!(result.is_ok());
    let proof = result.unwrap();
    assert_eq!(proof.id, proof_id);
    assert_eq!(proof.schema.unwrap().id, proof_schema_id);
    assert_eq!(proof.verifier_did.unwrap().id, did_id);
    assert!(proof.holder_did.is_none());
}

#[tokio::test]
async fn test_set_proof_state() {
    let TestSetupWithProof {
        repository,
        proof_id,
        db,
        ..
    } = setup_with_proof(
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_did_repository_mock(),
    )
    .await;

    let result = repository
        .set_proof_state(
            &proof_id,
            ProofState {
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                state: ProofStateEnum::Pending,
            },
        )
        .await;

    assert!(result.is_ok());
    let db_states = crate::entity::ProofState::find()
        .order_by_desc(proof_state::Column::CreatedDate)
        .all(&db)
        .await
        .unwrap();
    assert_eq!(db_states.len(), 2);
    assert_eq!(db_states[0].state, ProofRequestState::Pending);
}

#[tokio::test]
async fn test_set_proof_holder_did() {
    let TestSetupWithProof {
        repository,
        proof_id,
        organisation_id,
        db,
        ..
    } = setup_with_proof(
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_did_repository_mock(),
    )
    .await;

    let holder_did_id = Uuid::parse_str(
        &insert_did(&db, "holder", "did:holder", &organisation_id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    let result = repository
        .set_proof_holder_did(
            &proof_id,
            Did {
                id: holder_did_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "holder".to_string(),
                organisation_id,
                did: "did:holder".to_string(),
                did_type: DidType::Remote,
                did_method: "KEY".to_string(),
            },
        )
        .await;

    assert!(result.is_ok());

    let proof = get_proof_by_id(&db, &proof_id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert!(proof.holder_did_id.is_some());
    assert_eq!(proof.holder_did_id.unwrap(), holder_did_id.to_string());
}

#[tokio::test]
async fn test_set_proof_claims_success() {
    let claim = Claim {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: "value".to_string(),
        schema: None,
    };

    let mut claim_repository = MockClaimRepository::default();
    claim_repository
        .expect_create_claim_list()
        .times(1)
        .returning(|_| Ok(()));

    let TestSetupWithProof {
        repository,
        proof_id,
        db,
        claim_schema_ids,
        ..
    } = setup_with_proof(
        get_proof_schema_repository_mock(),
        Arc::from(claim_repository),
        get_did_repository_mock(),
    )
    .await;

    // necessary to pass db consistency checks
    claim::ActiveModel {
        id: Set(claim.id.to_string()),
        claim_schema_id: Set(claim_schema_ids[0].to_string()),
        value: Set("value".to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
    }
    .insert(&db)
    .await
    .unwrap();

    let result = repository.set_proof_claims(&proof_id, vec![claim]).await;
    assert!(result.is_ok());

    let db_proof_claims = crate::entity::ProofClaim::find().all(&db).await.unwrap();
    assert_eq!(db_proof_claims.len(), 1);
}