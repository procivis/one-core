use std::collections::HashSet;
use std::sync::Arc;

use one_core::model::claim::Claim;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::CredentialStateEnum;
use one_core::repository::DataRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::claim_schema_repository::{
    ClaimSchemaRepository, MockClaimSchemaRepository,
};
use one_core::repository::error::DataLayerError;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use shared_types::{
    ClaimId, ClaimSchemaId, CredentialId, CredentialSchemaId, IdentifierId, ProofId,
};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ClaimProvider;
use crate::entity::credential::CredentialRole;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{claim, claim_schema, proof, proof_claim};
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

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

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        false,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
        .await
        .unwrap();

    let claim_schema_ids: Vec<ClaimSchemaId> = (0..4).map(|_| Uuid::new_v4().into()).collect();
    for (index, id) in claim_schema_ids.iter().enumerate() {
        claim_schema::ActiveModel {
            id: Set(*id),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            key: Set(format!("TestKey-{index}")),
            datatype: Set("STRING".to_string()),
            array: Set(false),
            metadata: Set(false),
            credential_schema_id: Set(credential_schema_id),
            order: Set(index as i32),
            required: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();
    }

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
        &credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
        Uuid::new_v4().into(),
        CredentialRole::Issuer,
    )
    .await
    .unwrap();

    TestSetup {
        repository: Box::new(ClaimProvider {
            db: TransactionManagerImpl::new(db.clone()),
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
                metadata: false,
                required: true,
                translations: Default::default(),
            })
            .collect(),
        identifier_id,
        credential_schema_id,
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
            credential_id,
            claim_schemas
                .into_iter()
                .map(|schema| Claim {
                    id: Uuid::new_v4().into(),
                    value: Some("value".to_string()),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    selectively_disclosable: false,
                    schema: schema.into(),
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
            credential_id,
            claim_schemas
                .into_iter()
                .map(|schema| Claim {
                    id: Uuid::new_v4().into(),
                    value: Some("value".to_string()),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    schema: schema.into(),
                    selectively_disclosable: false,
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
        Uuid::new_v4().into(),
        CredentialRole::Issuer,
    )
    .await
    .unwrap()
    .id;

    repository
        .create_claim_list(
            credential_id,
            claim_schemas
                .iter()
                .map(|schema| Claim {
                    id: Uuid::new_v4().into(),
                    value: Some("value".to_string()),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    schema: schema.clone().into(),
                    selectively_disclosable: false,
                })
                .collect(),
        )
        .await
        .unwrap();

    repository
        .create_claim_list(
            credential_id_2,
            claim_schemas
                .into_iter()
                .map(|schema| Claim {
                    id: Uuid::new_v4().into(),
                    value: Some("value".to_string()),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    path: schema.key.to_owned(),
                    schema: schema.into(),
                    selectively_disclosable: false,
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
            id: Uuid::new_v4().into(),
            value: Some("value".to_string()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            path: schema.key.to_owned(),
            schema: schema.to_owned().into(),
            selectively_disclosable: false,
        })
        .collect();
    repository
        .create_claim_list(credential_id, claims.clone())
        .await
        .unwrap();

    // single item
    let result = repository.get_claim_list(vec![claims[0].id]).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, claims[0].id);

    // two items - different order
    let result = repository
        .get_claim_list(vec![claims[3].id, claims[1].id])
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].id, claims[3].id);
    assert_eq!(result[1].id, claims[1].id);

    // one item missing
    let result = repository
        .get_claim_list(vec![claims[0].id, Uuid::new_v4().into()])
        .await;
    assert!(matches!(
        result,
        Err(DataLayerError::IncompleteClaimsList {
            expected: 2,
            got: 1
        })
    ));
}

/// The claim schemas are loaded lazily, but the whole batch of returned claims shares a single
/// loader, so resolving any of them issues exactly one query for all of them.
#[tokio::test]
async fn test_get_claim_list_lazily_loads_schemas_as_a_single_batch() {
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .withf(|ids| ids.len() == 2)
        .returning(|ids| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    key: format!("key {id}"),
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
        claim_schemas,
        credential_id,
        ..
    } = setup(Arc::from(claim_schema_repository)).await;

    let claims: Vec<Claim> = claim_schemas
        .iter()
        .map(|schema| Claim {
            id: Uuid::new_v4().into(),
            value: Some("value".to_string()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            path: schema.key.to_owned(),
            schema: schema.to_owned().into(),
            selectively_disclosable: false,
        })
        .collect();
    repository
        .create_claim_list(credential_id, claims.clone())
        .await
        .unwrap();

    let result = repository
        .get_claim_list(vec![claims[2].id, claims[1].id])
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].id, claims[2].id);
    assert_eq!(result[1].id, claims[1].id);

    assert_eq!(result[1].value, claims[1].value);

    // the schema id is available without loading the relation
    assert_eq!(result[0].schema.id(), claim_schemas[2].id);
    assert_eq!(result[1].schema.id(), claim_schemas[1].id);

    // resolving both relations only triggers the single batched query asserted on the mock above
    assert_eq!(
        result[0].schema.as_ref().await.unwrap().id,
        claim_schemas[2].id
    );
    assert_eq!(
        result[1].schema.as_ref().await.unwrap().id,
        claim_schemas[1].id
    );
}

async fn sibling_credential(setup: &TestSetup) -> CredentialId {
    use sea_orm::IntoActiveModel;

    use crate::entity::credential;
    let mut model = credential::Entity::find_by_id(setup.credential_id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    let id = Uuid::new_v4().into();
    model.id = Set(id);
    model.insert(&setup.db).await.unwrap();
    id
}

fn stored_claim(setup: &TestSetup) -> Claim {
    Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("shared".into()),
        path: "name".into(),
        selectively_disclosable: true,
        schema: setup.claim_schemas[0].clone().into(),
    }
}

struct SharedClaimSetup {
    db: DatabaseConnection,
    repositories: crate::DataLayer,
    credential_ids: [CredentialId; 2],
    shared: Claim,
}

async fn setup_with_shared_claim() -> SharedClaimSetup {
    let setup = setup(get_claim_schema_repository_mock()).await;
    let second = sibling_credential(&setup).await;
    let shared = stored_claim(&setup);
    let repositories = crate::DataLayer::build(setup.db.clone(), vec![]);
    let credential_ids = [setup.credential_id, second];
    for credential_id in credential_ids {
        repositories
            .get_claim_repository()
            .create_claim_list(credential_id, vec![shared.clone()])
            .await
            .unwrap();
    }
    SharedClaimSetup {
        db: setup.db,
        repositories,
        credential_ids,
        shared,
    }
}

async fn insert_proof_for_claim(
    db: &DatabaseConnection,
    claim_id: ClaimId,
    credential_ids: &[CredentialId],
) -> ProofId {
    let proof_id = Uuid::new_v4().into();
    proof::ActiveModel {
        id: Set(proof_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        protocol: Set("OPENID4VP_FINAL1".into()),
        transport: Set("HTTP".into()),
        state: Set(proof::ProofRequestState::Accepted),
        role: Set(proof::ProofRole::Holder),
        ..Default::default()
    }
    .insert(db)
    .await
    .unwrap();
    for credential_id in credential_ids {
        proof_claim::ActiveModel {
            proof_id: Set(proof_id),
            credential_id: Set(*credential_id),
            claim_id: Set(claim_id),
        }
        .insert(db)
        .await
        .unwrap();
    }
    proof_id
}

#[tokio::test]
async fn credentials_can_share_one_stored_claim() {
    let SharedClaimSetup {
        db,
        repositories,
        credential_ids,
        shared,
    } = setup_with_shared_claim().await;

    for credential_id in credential_ids {
        let claims = repositories
            .get_claim_repository()
            .get_claims_for_credential(credential_id)
            .await
            .unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, shared.id);
    }
    assert_eq!(claim::Entity::find().all(&db).await.unwrap().len(), 1);
}

#[tokio::test]
async fn separate_proofs_preserve_shared_claim_source_credentials() {
    let SharedClaimSetup {
        db,
        repositories,
        credential_ids,
        shared,
    } = setup_with_shared_claim().await;
    let proofs = repositories.get_proof_repository();

    for credential_id in credential_ids {
        let proof_id = insert_proof_for_claim(&db, shared.id, &[credential_id]).await;
        let proof = proofs.get_proof(&proof_id, None).await.unwrap();
        let inputs = proof.claims.as_ref().await.unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].credential.id(), credential_id);
        assert_eq!(inputs[0].claim.id, shared.id);
    }
}

#[tokio::test]
async fn one_proof_preserves_both_sources_of_a_shared_claim() {
    let SharedClaimSetup {
        db,
        repositories,
        credential_ids,
        shared,
    } = setup_with_shared_claim().await;
    let proof_id = insert_proof_for_claim(&db, shared.id, &credential_ids).await;

    let proof = repositories
        .get_proof_repository()
        .get_proof(&proof_id, None)
        .await
        .unwrap();
    let inputs = proof.claims.as_ref().await.unwrap();
    assert_eq!(inputs.len(), 2);
    assert!(inputs.iter().all(|input| input.claim.id == shared.id));
    assert_eq!(
        inputs
            .iter()
            .map(|input| input.credential.id())
            .collect::<HashSet<_>>(),
        HashSet::from(credential_ids)
    );
}

#[tokio::test]
async fn conflicting_claim_insertion_preserves_existing_associations() {
    let SharedClaimSetup {
        db,
        repositories,
        credential_ids,
        shared,
    } = setup_with_shared_claim().await;
    let conflicting = Claim {
        value: Some("changed".into()),
        ..shared.clone()
    };

    let result = repositories
        .get_claim_repository()
        .create_claim_list(credential_ids[1], vec![conflicting])
        .await;

    assert!(matches!(result, Err(DataLayerError::AlreadyExists)));
    for credential_id in credential_ids {
        let claims = repositories
            .get_claim_repository()
            .get_claims_for_credential(credential_id)
            .await
            .unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, shared.id);
        assert_eq!(claims[0].value, shared.value);
    }
    assert_eq!(claim::Entity::find().all(&db).await.unwrap().len(), 1);
}

#[tokio::test]
async fn detaching_shared_claim_preserves_other_credential_and_proof() {
    let SharedClaimSetup {
        db,
        repositories,
        credential_ids: [first, second],
        shared,
    } = setup_with_shared_claim().await;
    let proof_id = insert_proof_for_claim(&db, shared.id, &[second]).await;
    let claims = repositories.get_claim_repository();
    claims.delete_claims_for_credential(second).await.unwrap();

    let first_claims = claims.get_claims_for_credential(first).await.unwrap();
    assert_eq!(first_claims.len(), 1);
    assert_eq!(first_claims[0].id, shared.id);
    assert_eq!(first_claims[0].value, shared.value);
    assert!(
        claims
            .get_claims_for_credential(second)
            .await
            .unwrap()
            .is_empty()
    );
    let proof = repositories
        .get_proof_repository()
        .get_proof(&proof_id, None)
        .await
        .unwrap();
    let inputs = proof.claims.as_ref().await.unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].credential.id(), second);
    assert_eq!(inputs[0].claim.id, shared.id);
    assert_eq!(inputs[0].claim.value, shared.value);
}

#[tokio::test]
async fn shared_claim_is_deleted_after_proofs_then_credentials_are_detached() {
    let SharedClaimSetup {
        db,
        repositories,
        credential_ids: [first, second],
        shared,
    } = setup_with_shared_claim().await;
    let proof_id = insert_proof_for_claim(&db, shared.id, &[first, second]).await;
    let claims = repositories.get_claim_repository();

    repositories
        .get_proof_repository()
        .delete_proof_claims(&proof_id)
        .await
        .unwrap();
    for credential_id in [first, second] {
        let associated = claims
            .get_claims_for_credential(credential_id)
            .await
            .unwrap();
        assert_eq!(associated.len(), 1);
        assert_eq!(associated[0].id, shared.id);
    }
    claims.delete_claims_for_credential(first).await.unwrap();
    assert!(
        claim::Entity::find_by_id(shared.id)
            .one(&db)
            .await
            .unwrap()
            .is_some()
    );
    claims.delete_claims_for_credential(second).await.unwrap();
    assert!(
        claim::Entity::find_by_id(shared.id)
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn shared_claim_is_deleted_after_credentials_then_proofs_are_detached() {
    let SharedClaimSetup {
        db,
        repositories,
        credential_ids,
        shared,
    } = setup_with_shared_claim().await;
    let mut proof_ids = Vec::new();
    for credential_id in credential_ids {
        proof_ids.push(insert_proof_for_claim(&db, shared.id, &[credential_id]).await);
    }
    let proofs = repositories.get_proof_repository();

    repositories
        .get_claim_repository()
        .delete_claims_for_credentials(HashSet::from(credential_ids))
        .await
        .unwrap();
    for proof_id in &proof_ids {
        let proof = proofs.get_proof(proof_id, None).await.unwrap();
        let inputs = proof.claims.as_ref().await.unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].claim.id, shared.id);
    }
    proofs.delete_proof_claims(&proof_ids[0]).await.unwrap();
    assert!(
        claim::Entity::find_by_id(shared.id)
            .one(&db)
            .await
            .unwrap()
            .is_some()
    );
    proofs.delete_proof_claims(&proof_ids[1]).await.unwrap();
    assert!(
        claim::Entity::find_by_id(shared.id)
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn bulk_detach_preserves_remaining_credential_and_distinct_claim_ids() {
    use crate::entity::claim;
    let setup = setup(get_claim_schema_repository_mock()).await;
    let second = sibling_credential(&setup).await;
    let third = sibling_credential(&setup).await;
    let shared = stored_claim(&setup);
    for credential_id in [setup.credential_id, second, third] {
        setup
            .repository
            .create_claim_list(credential_id, vec![shared.clone()])
            .await
            .unwrap();
    }
    setup
        .repository
        .delete_claims_for_credentials(HashSet::from([setup.credential_id, second]))
        .await
        .unwrap();
    assert_eq!(
        setup
            .repository
            .get_claims_for_credential(third)
            .await
            .unwrap()[0]
            .id,
        shared.id
    );
    // Equal contents under a fresh ID remain separate until the deduplication step.
    let distinct = Claim {
        id: Uuid::new_v4().into(),
        ..shared.clone()
    };
    setup
        .repository
        .create_claim_list(second, vec![distinct.clone()])
        .await
        .unwrap();
    assert_eq!(claim::Entity::find().all(&setup.db).await.unwrap().len(), 2);
    setup
        .repository
        .delete_claims_for_credential(third)
        .await
        .unwrap();
    assert!(
        claim::Entity::find_by_id(shared.id)
            .one(&setup.db)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        claim::Entity::find_by_id(distinct.id)
            .one(&setup.db)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn failed_claim_association_does_not_leave_orphan_rows() {
    use crate::entity::claim;
    let setup = setup(get_claim_schema_repository_mock()).await;
    let first = stored_claim(&setup);
    assert!(
        setup
            .repository
            .create_claim_list(Uuid::new_v4().into(), vec![first.clone()])
            .await
            .is_err()
    );
    assert!(
        claim::Entity::find()
            .all(&setup.db)
            .await
            .unwrap()
            .is_empty()
    );
    setup
        .repository
        .create_claim_list(setup.credential_id, vec![first.clone()])
        .await
        .unwrap();
    let duplicate_path = Claim {
        id: Uuid::new_v4().into(),
        ..first.clone()
    };
    assert!(
        setup
            .repository
            .create_claim_list(setup.credential_id, vec![duplicate_path])
            .await
            .is_err()
    );
    assert_eq!(claim::Entity::find().all(&setup.db).await.unwrap().len(), 1);
    // Reattaching the same association is harmless.
    setup
        .repository
        .create_claim_list(setup.credential_id, vec![first.clone()])
        .await
        .unwrap();
    assert_eq!(
        setup
            .repository
            .get_claims_for_credential(setup.credential_id)
            .await
            .unwrap()
            .len(),
        1
    );
}
