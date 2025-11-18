use std::sync::Arc;

use mockall::predicate::eq;
use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialStateEnum,
};
use one_core::model::did::{Did, DidRelations, DidType};
use one_core::model::identifier::{
    Identifier, IdentifierRelations, IdentifierState, IdentifierType,
};
use one_core::model::interaction::{
    Interaction, InteractionId, InteractionRelations, InteractionType,
};
use one_core::model::key::{Key, KeyRelations};
use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::ListPagination;
use one_core::model::proof::{
    GetProofQuery, Proof, ProofClaimRelations, ProofRelations, ProofRole, ProofStateEnum,
};
use one_core::model::proof_schema::{ProofSchema, ProofSchemaRelations};
use one_core::repository::certificate_repository::{
    CertificateRepository, MockCertificateRepository,
};
use one_core::repository::claim_repository::{ClaimRepository, MockClaimRepository};
use one_core::repository::credential_repository::{CredentialRepository, MockCredentialRepository};
use one_core::repository::identifier_repository::{IdentifierRepository, MockIdentifierRepository};
use one_core::repository::interaction_repository::{
    InteractionRepository, MockInteractionRepository,
};
use one_core::repository::key_repository::{KeyRepository, MockKeyRepository};
use one_core::repository::proof_repository::ProofRepository;
use one_core::repository::proof_schema_repository::{
    MockProofSchemaRepository, ProofSchemaRepository,
};
use one_core::service::proof::dto::ProofFilterValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use shared_types::{
    ClaimSchemaId, DidId, IdentifierId, KeyId, OrganisationId, ProofId, ProofSchemaId,
};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ProofProvider;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::key_did::KeyRole;
use crate::entity::{blob, claim, credential, interaction, proof_claim};
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn ProofRepository>,
    pub organisation_id: OrganisationId,
    pub proof_schema_id: ProofSchemaId,
    pub did_id: DidId,
    pub identifier_id: IdentifierId,
    pub claim_schema_ids: Vec<ClaimSchemaId>,
    pub interaction_id: InteractionId,
    pub key_id: KeyId,
}

async fn setup(
    credential_repository: Arc<dyn CredentialRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    key_repository: Arc<dyn KeyRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = Uuid::new_v4().into();
    insert_organisation_to_database(&db, Some(organisation_id), None)
        .await
        .unwrap();

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        "JWT",
        "NONE",
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: "test",
            required: i % 2 == 0,
            order: i as u32,
            datatype: "STRING",
            array: false,
            metadata: false,
        })
        .collect();

    let claim_input = ProofInput {
        credential_schema_id,
        claims: &new_claim_schemas,
    };

    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    let proof_schema_id = insert_proof_schema_with_claims_to_database(
        &db,
        None,
        vec![&claim_input],
        organisation_id,
        "proof schema",
    )
    .await
    .unwrap();

    let did_id = insert_did_key(
        &db,
        "verifier",
        Uuid::new_v4(),
        "did:key:123".parse().unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();

    let key_id = insert_key_to_database(
        &db,
        "ED25519".to_string(),
        vec![],
        vec![],
        None,
        organisation_id,
    )
    .await
    .unwrap();

    insert_key_did(&db, did_id, key_id, KeyRole::AssertionMethod)
        .await
        .unwrap();

    let identifier_id = insert_identifier(
        &db,
        "verifier",
        Uuid::new_v4(),
        Some(did_id),
        organisation_id,
        false,
    )
    .await
    .unwrap();

    let interaction_id = Uuid::parse_str(
        &insert_interaction(
            &db,
            &[1, 2, 3],
            organisation_id,
            None,
            interaction::InteractionType::Verification,
        )
        .await
        .unwrap(),
    )
    .unwrap();

    TestSetup {
        repository: Box::new(ProofProvider {
            db: TransactionManagerImpl::new(db.clone()),
            proof_schema_repository,
            claim_repository,
            credential_repository,
            identifier_repository,
            interaction_repository,
            key_repository,
            certificate_repository,
        }),
        db,
        organisation_id,
        proof_schema_id,
        did_id,
        identifier_id,
        claim_schema_ids: new_claim_schemas.into_iter().map(|item| item.id).collect(),
        interaction_id,
        key_id,
    }
}

struct TestSetupWithProof {
    pub repository: Box<dyn ProofRepository>,
    pub organisation_id: OrganisationId,
    pub proof_schema_id: ProofSchemaId,
    pub identifier_id: IdentifierId,
    pub proof_id: ProofId,
    pub db: DatabaseConnection,
    pub claim_schema_ids: Vec<ClaimSchemaId>,
    pub interaction_id: InteractionId,
    pub key_id: KeyId,
}

async fn setup_with_proof(
    credential_repository: Arc<dyn CredentialRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    key_repository: Arc<dyn KeyRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
) -> TestSetupWithProof {
    let TestSetup {
        repository,
        db,
        proof_schema_id,
        identifier_id,
        organisation_id,
        claim_schema_ids,
        interaction_id,
        key_id,
        ..
    } = setup(
        credential_repository,
        proof_schema_repository,
        claim_repository,
        identifier_repository,
        interaction_repository,
        key_repository,
        certificate_repository,
    )
    .await;

    let proof_id = insert_proof_request_to_database(
        &db,
        identifier_id,
        None,
        &proof_schema_id,
        key_id,
        Some(interaction_id.to_string()),
        None,
        None,
    )
    .await
    .unwrap();

    TestSetupWithProof {
        repository,
        organisation_id,
        proof_schema_id,
        identifier_id,
        proof_id,
        db,
        claim_schema_ids,
        interaction_id,
        key_id,
    }
}

fn get_proof_schema_repository_mock() -> Arc<dyn ProofSchemaRepository> {
    Arc::from(MockProofSchemaRepository::default())
}

fn get_claim_repository_mock() -> Arc<dyn ClaimRepository> {
    Arc::from(MockClaimRepository::default())
}

fn get_credential_repository_mock() -> Arc<dyn CredentialRepository> {
    Arc::from(MockCredentialRepository::default())
}

fn get_identifier_repository_mock() -> Arc<dyn IdentifierRepository> {
    Arc::from(MockIdentifierRepository::default())
}

fn get_interaction_repository_mock() -> Arc<dyn InteractionRepository> {
    Arc::from(MockInteractionRepository::default())
}

fn get_key_repository_mock() -> Arc<dyn KeyRepository> {
    Arc::from(MockKeyRepository::default())
}

fn get_certificate_repository_mock() -> Arc<dyn CertificateRepository> {
    Arc::from(MockCertificateRepository::default())
}

#[tokio::test]
async fn test_create_proof_success() {
    let TestSetup {
        repository,
        db,
        proof_schema_id,
        did_id,
        identifier_id,
        key_id,
        ..
    } = setup(
        get_credential_repository_mock(),
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_identifier_repository_mock(),
        get_interaction_repository_mock(),
        get_key_repository_mock(),
        get_certificate_repository_mock(),
    )
    .await;

    let proof_id = Uuid::new_v4().into();
    let proof = Proof {
        id: proof_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        protocol: "test".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: proof_schema_id,
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: None,
            input_schemas: None,
        }),
        claims: None,
        holder_identifier: None,
        verifier_key: Some(Key {
            id: key_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "".to_string(),
            key_reference: None,
            storage_type: "".to_string(),
            key_type: "".to_string(),
            organisation: None,
        }),
        verifier_certificate: None,
        verifier_identifier: Some(Identifier {
            id: identifier_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "verifier".to_string(),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: did_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "verifier".to_string(),
                did: "did:key:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            key: None,
            certificates: None,
        }),
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };

    let result = repository.create_proof(proof).await.unwrap();
    assert_eq!(result, proof_id);

    assert_eq!(
        crate::entity::proof::Entity::find()
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
        get_credential_repository_mock(),
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_identifier_repository_mock(),
        get_interaction_repository_mock(),
        get_key_repository_mock(),
        get_certificate_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof_list(GetProofQuery {
            pagination: Some(ListPagination {
                page_size: 1,
                page: 0,
            }),
            filtering: ProofFilterValue::OrganisationId(organisation_id)
                .condition()
                .into(),
            sorting: None,
            include: None,
        })
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
        get_credential_repository_mock(),
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_identifier_repository_mock(),
        get_interaction_repository_mock(),
        get_key_repository_mock(),
        get_certificate_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof(&Uuid::new_v4().into(), &ProofRelations::default())
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_proof_no_relations() {
    let TestSetupWithProof {
        repository,
        proof_id,
        ..
    } = setup_with_proof(
        get_credential_repository_mock(),
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_identifier_repository_mock(),
        get_interaction_repository_mock(),
        get_key_repository_mock(),
        get_certificate_repository_mock(),
    )
    .await;

    let proof = repository
        .get_proof(&proof_id, &ProofRelations::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(proof.id, proof_id);
}

#[tokio::test]
async fn test_get_proof_with_relations() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
                input_schemas: None,
            }))
        });

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_get_interaction()
        .times(1)
        .returning(|id, _, _| {
            Ok(Some(Interaction {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(vec![1, 2, 3]),
                organisation: None,
                nonce_id: None,
                interaction_type: InteractionType::Verification,
            }))
        });

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .times(1)
        .returning(|id, _| {
            Ok(Some(Identifier {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "identifier".to_string(),
                r#type: IdentifierType::Did,
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: None,
                did: Some(Did {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "verifier".to_string(),
                    did: "did:key:123".parse().unwrap(),
                    did_type: DidType::Local,
                    did_method: "KEY".to_string(),
                    organisation: None,
                    keys: None,
                    deactivated: false,
                    log: None,
                }),
                key: None,
                certificates: None,
            }))
        });

    let credential_id = Uuid::new_v4().into();
    let claim_id = Uuid::new_v4();
    let mut claim_repository = MockClaimRepository::default();
    claim_repository
        .expect_get_claim_list()
        .once()
        .with(eq(vec![claim_id]), eq(ClaimRelations::default()))
        .returning(move |ids, _| {
            Ok(vec![Claim {
                id: ids[0],
                credential_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                value: Some("value".to_string()),
                path: String::new(),
                schema: None,
                selectively_disclosable: false,
            }])
        });

    let mut credential_repository = MockCredentialRepository::default();
    credential_repository
        .expect_get_credential_by_claim_id()
        .once()
        .with(eq(claim_id), eq(CredentialRelations::default()))
        .returning(move |_, _| {
            Ok(Some(Credential {
                id: credential_id,
                created_date: get_dummy_date(),
                issuance_date: None,
                last_modified: get_dummy_date(),
                deleted_at: None,
                protocol: "protocol".to_string(),
                redirect_uri: None,
                role: CredentialRole::Verifier,
                state: CredentialStateEnum::Accepted,
                suspend_end_date: None,
                claims: None,
                issuer_identifier: None,
                issuer_certificate: None,
                holder_identifier: None,
                schema: None,
                interaction: None,
                key: None,
                profile: None,
                credential_blob_id: Some(Uuid::new_v4().into()),
                wallet_unit_attestation_blob_id: None,
                wallet_app_attestation_blob_id: None,
            }))
        });

    let mut key_repository = MockKeyRepository::default();
    key_repository
        .expect_get_key()
        .once()
        .returning(|key_id, _| {
            Ok(Some(Key {
                id: key_id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "".to_string(),
                key_reference: None,
                storage_type: "".to_string(),
                key_type: "".to_string(),
                organisation: None,
            }))
        });

    let TestSetupWithProof {
        repository,
        proof_id,
        proof_schema_id,
        interaction_id,
        claim_schema_ids,
        db,
        organisation_id,
        key_id,
        ..
    } = setup_with_proof(
        Arc::from(credential_repository),
        Arc::from(proof_schema_repository),
        Arc::from(claim_repository),
        Arc::from(identifier_repository),
        Arc::from(interaction_repository),
        Arc::from(key_repository),
        get_certificate_repository_mock(),
    )
    .await;

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema 1",
        "JWT",
        "NONE",
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

    let blob_id = Uuid::new_v4().into();
    blob::ActiveModel {
        id: Set(blob_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        value: Set(vec![0, 0, 0, 0]),
        r#type: Set(blob::BlobType::Credential),
    }
    .insert(&db)
    .await
    .unwrap();

    credential::ActiveModel {
        id: Set(credential_id),
        credential_schema_id: Set(credential_schema_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(Some(get_dummy_date())),
        redirect_uri: Set(None),
        deleted_at: Set(None),
        protocol: Set("OPENID4VCI_DRAFT13".to_owned()),
        role: Set(credential::CredentialRole::Issuer),
        interaction_id: Set(None),
        key_id: Set(None),
        state: Set(credential::CredentialState::Accepted),
        credential_blob_id: Set(Some(blob_id)),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    claim::ActiveModel {
        id: Set(claim_id.into()),
        credential_id: Set(credential_id),
        claim_schema_id: Set(claim_schema_ids[0]),
        value: Set(Some("value".into())),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();
    proof_claim::ActiveModel {
        claim_id: Set(claim_id.to_string()),
        proof_id: Set(proof_id.to_string()),
    }
    .insert(&db)
    .await
    .unwrap();

    let proof = repository
        .get_proof(
            &proof_id,
            &ProofRelations {
                claims: Some(ProofClaimRelations {
                    claim: ClaimRelations::default(),
                    credential: Some(CredentialRelations::default()),
                }),
                schema: Some(ProofSchemaRelations::default()),
                verifier_identifier: Some(IdentifierRelations {
                    did: Some(DidRelations::default()),
                    ..Default::default()
                }),
                holder_identifier: Some(IdentifierRelations {
                    did: Some(DidRelations::default()),
                    ..Default::default()
                }),
                verifier_key: Some(KeyRelations::default()),
                interaction: Some(InteractionRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(proof.id, proof_id);
    assert_eq!(proof.schema.unwrap().id, proof_schema_id);
    assert!(proof.holder_identifier.is_none());
    assert_eq!(proof.interaction.unwrap().id, interaction_id);
    assert_eq!(proof.verifier_key.unwrap().id, key_id);

    let claims = proof.claims.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].claim.id, claim_id);
    assert_eq!(claims[0].credential.to_owned().unwrap().id, credential_id);
}

#[tokio::test]
async fn test_get_proof_by_interaction_id_missing() {
    let TestSetupWithProof { repository, .. } = setup_with_proof(
        get_credential_repository_mock(),
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_identifier_repository_mock(),
        get_interaction_repository_mock(),
        get_key_repository_mock(),
        get_certificate_repository_mock(),
    )
    .await;

    let result = repository
        .get_proof_by_interaction_id(&Uuid::new_v4(), &ProofRelations::default())
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_proof_by_interaction_id_success() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
                input_schemas: None,
            }))
        });

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_get_interaction()
        .times(1)
        .returning(|id, _, _| {
            Ok(Some(Interaction {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(vec![1, 2, 3]),
                organisation: None,
                nonce_id: None,
                interaction_type: InteractionType::Verification,
            }))
        });

    let mut key_repository = MockKeyRepository::default();
    key_repository
        .expect_get_key()
        .once()
        .returning(|key_id, _| {
            Ok(Some(Key {
                id: key_id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "".to_string(),
                key_reference: None,
                storage_type: "".to_string(),
                key_type: "".to_string(),
                organisation: None,
            }))
        });

    let TestSetupWithProof {
        repository,
        proof_id,
        interaction_id,
        ..
    } = setup_with_proof(
        get_credential_repository_mock(),
        Arc::from(proof_schema_repository),
        get_claim_repository_mock(),
        get_identifier_repository_mock(),
        Arc::from(interaction_repository),
        Arc::from(key_repository),
        get_certificate_repository_mock(),
    )
    .await;

    let proof = repository
        .get_proof_by_interaction_id(
            &interaction_id,
            &ProofRelations {
                claims: Some(ProofClaimRelations::default()),
                schema: Some(ProofSchemaRelations::default()),
                verifier_key: Some(KeyRelations::default()),
                interaction: Some(InteractionRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(proof.id, proof_id);
    assert_eq!(proof.interaction.unwrap().id, interaction_id);
}

#[tokio::test]
async fn test_set_proof_claims_success() {
    let TestSetupWithProof {
        repository,
        proof_id,
        db,
        claim_schema_ids,
        organisation_id,
        identifier_id,
        ..
    } = setup_with_proof(
        get_credential_repository_mock(),
        get_proof_schema_repository_mock(),
        get_claim_repository_mock(),
        get_identifier_repository_mock(),
        get_interaction_repository_mock(),
        get_key_repository_mock(),
        get_certificate_repository_mock(),
    )
    .await;

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema 1",
        "JWT",
        "NONE",
        Some(KeyStorageSecurity::Basic),
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
    )
    .await
    .unwrap();

    let claim = Claim {
        id: Uuid::new_v4(),
        credential_id: credential.id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("value".to_string()),
        schema: None,
        path: String::default(),
        selectively_disclosable: false,
    };

    // necessary to pass db consistency checks
    claim::ActiveModel {
        id: Set(claim.id.into()),
        credential_id: Set(credential.id),
        claim_schema_id: Set(claim_schema_ids[0]),
        value: Set(Some("value".into())),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    let result = repository.set_proof_claims(&proof_id, vec![claim]).await;
    assert!(result.is_ok());

    let db_proof_claims = crate::entity::proof_claim::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(db_proof_claims.len(), 1);
}
