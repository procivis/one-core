use std::sync::Arc;

use mockall::predicate::eq;
use one_core::model::claim::Claim;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{Did, DidType};
use one_core::model::identifier::{Identifier, IdentifierData, IdentifierState};
use one_core::model::interaction::{Interaction, InteractionType};
use one_core::model::key::Key;
use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::ListPagination;
use one_core::model::proof::{Proof, ProofListQuery, ProofRelations, ProofRole, ProofStateEnum};
use one_core::model::proof_schema::ProofSchema;
use one_core::repository::certificate_repository::{
    CertificateRepository, MockCertificateRepository,
};
use one_core::repository::claim_repository::{ClaimRepository, MockClaimRepository};
use one_core::repository::credential_repository::{CredentialRepository, MockCredentialRepository};
use one_core::repository::did_repository::MockDidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::{IdentifierRepository, MockIdentifierRepository};
use one_core::repository::identifier_trust_information_repository::MockIdentifierTrustInformationRepository;
use one_core::repository::interaction_repository::{
    InteractionRepository, MockInteractionRepository,
};
use one_core::repository::key_repository::{KeyRepository, MockKeyRepository};
use one_core::repository::organisation_repository::MockOrganisationRepository;
use one_core::repository::proof_repository::ProofRepository;
use one_core::repository::proof_schema_repository::{
    MockProofSchemaRepository, ProofSchemaRepository,
};
use one_core::service::proof::dto::ProofFilterValue;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use shared_types::{
    ClaimId, ClaimSchemaId, DidId, IdentifierId, InteractionId, KeyId, OrganisationId, ProofId,
    ProofSchemaId,
};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ProofProvider;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::key_did::KeyRole;
use crate::entity::{blob, claim, credential, interaction, proof, proof_claim};
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
    insert_organisation_to_database(&db, Some(organisation_id))
        .await
        .unwrap();

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

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: format!("test-{i}"),
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

    let interaction_id = insert_interaction(
        &db,
        &[1, 2, 3],
        organisation_id,
        None,
        interaction::InteractionType::Verification,
    )
    .await
    .unwrap();

    TestSetup {
        repository: Box::new(ProofProvider {
            db: TransactionManagerImpl::new(db.clone()),
            proof_schema_repository,
            claim_repository,
            credential_repository,
            identifier_repository,
            interaction_repository,
            did_repository: Arc::new(MockDidRepository::default()),
            key_repository,
            certificate_repository,
            organisation_repository: Arc::new(MockOrganisationRepository::default()),
            trust_information_repository: Arc::new(
                MockIdentifierTrustInformationRepository::default(),
            ),
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
        &proof_schema_id,
        key_id,
        Some(interaction_id),
        None,
        None,
        proof::ProofRole::Verifier,
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
        ecosystem: None,
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
            ecosystem: None,
            id: proof_schema_id,
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: dummy_organisation(None).into(),
            input_schemas: Default::default(),
        }),
        claims: None,
        verifier_key: Some(Key {
            id: key_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "".to_string(),
            key_reference: None,
            storage_type: "".to_string(),
            key_type: "".to_string(),
            organisation: dummy_organisation(None).into(),
        }),
        verifier_certificate: None,
        verifier_identifier: Some(Identifier {
            id: identifier_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "verifier".to_string(),
            data: IdentifierData::Did(
                (Did {
                    deleted_at: None,
                    id: did_id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "verifier".to_string(),
                    did: "did:key:123".parse().unwrap(),
                    did_type: DidType::Local,
                    did_method: "KEY".into(),
                    organisation: dummy_organisation(None).into(),
                    keys: Default::default(),
                    deactivated: false,
                    log: None,
                })
                .into(),
            ),
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: dummy_organisation(None).into(),
            trust_information: Default::default(),
        }),
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
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
        .get_proof_list(ProofListQuery {
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
        .get_proof(&Uuid::new_v4().into(), &ProofRelations::default(), None)
        .await;
    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
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
        .get_proof(&proof_id, &ProofRelations::default(), None)
        .await
        .unwrap();

    assert_eq!(proof.id, proof_id);
}

#[tokio::test]
async fn test_get_proof_with_relations() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|id| {
            Ok(ProofSchema {
                ecosystem: None,
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: dummy_organisation(None).into(),
                input_schemas: Default::default(),
            })
        });

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_get_interaction()
        .times(1)
        .returning(|id, _| {
            Ok(Interaction {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(vec![1, 2, 3]),
                organisation: dummy_organisation(None).into(),
                nonce_id: None,
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: None,
            })
        });

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository.expect_get().times(1).returning(|id| {
        Ok(Identifier {
            id: id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "identifier".to_string(),
            data: IdentifierData::Did(
                (Did {
                    deleted_at: None,
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "verifier".to_string(),
                    did: "did:key:123".parse().unwrap(),
                    did_type: DidType::Local,
                    did_method: "KEY".into(),
                    organisation: dummy_organisation(None).into(),
                    keys: Default::default(),
                    deactivated: false,
                    log: None,
                })
                .into(),
            ),
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: dummy_organisation(None).into(),
            trust_information: Default::default(),
        })
    });

    let credential_id = Uuid::new_v4().into();
    let claim_id: ClaimId = Uuid::new_v4().into();
    let mut claim_repository = MockClaimRepository::default();
    claim_repository
        .expect_get_claim_list()
        .once()
        .with(eq(vec![claim_id]))
        .returning(move |ids| {
            Ok(vec![Claim {
                id: ids[0],
                credential_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                value: Some("value".to_string()),
                path: String::new(),
                schema: dummy_claim_schema(Uuid::new_v4().into()).into(),
                selectively_disclosable: false,
            }])
        });

    let mut key_repository = MockKeyRepository::default();
    key_repository.expect_get_key().once().returning(|key_id| {
        Ok(Key {
            id: key_id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "".to_string(),
            key_reference: None,
            storage_type: "".to_string(),
            key_type: "".to_string(),
            organisation: dummy_organisation(None).into(),
        })
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
        get_credential_repository_mock(),
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
        false,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
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
        r#type: Set(credential::CredentialType::Single),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    claim::ActiveModel {
        id: Set(claim_id),
        credential_id: Set(credential_id),
        claim_schema_id: Set(claim_schema_ids[0]),
        value: Set(Some("value".into())),
        path: Set("path".into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        selectively_disclosable: Set(false),
    }
    .insert(&db)
    .await
    .unwrap();
    proof_claim::ActiveModel {
        claim_id: Set(claim_id),
        proof_id: Set(proof_id),
    }
    .insert(&db)
    .await
    .unwrap();

    let proof = repository
        .get_proof(
            &proof_id,
            &ProofRelations {
                claims: Some(Default::default()),
                schema: Some(Default::default()),
                verifier_identifier: Some(Default::default()),
                verifier_key: Some(Default::default()),
                interaction: Some(Default::default()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(proof.id, proof_id);
    assert_eq!(proof.schema.unwrap().id, proof_schema_id);
    assert_eq!(proof.interaction.unwrap().id, interaction_id);
    assert_eq!(proof.verifier_key.unwrap().id, key_id);

    let claims = proof.claims.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].claim.id, claim_id);
    assert_eq!(claims[0].credential.id(), credential_id);
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
        .get_proof_by_interaction_id(&Uuid::new_v4().into(), &ProofRelations::default())
        .await;
    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
}

#[tokio::test]
async fn test_get_proof_by_interaction_id_success() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|id| {
            Ok(ProofSchema {
                ecosystem: None,
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: dummy_organisation(None).into(),
                input_schemas: Default::default(),
            })
        });

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_get_interaction()
        .times(1)
        .returning(|id, _| {
            Ok(Interaction {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(vec![1, 2, 3]),
                organisation: dummy_organisation(None).into(),
                nonce_id: None,
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: None,
            })
        });

    let mut key_repository = MockKeyRepository::default();
    key_repository.expect_get_key().once().returning(|key_id| {
        Ok(Key {
            id: key_id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "".to_string(),
            key_reference: None,
            storage_type: "".to_string(),
            key_type: "".to_string(),
            organisation: dummy_organisation(None).into(),
        })
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
                claims: Some(Default::default()),
                schema: Some(Default::default()),
                verifier_key: Some(Default::default()),
                interaction: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
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
        false,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

    insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
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
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    let claim = Claim {
        id: Uuid::new_v4().into(),
        credential_id: credential.id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("value".to_string()),
        schema: dummy_claim_schema(claim_schema_ids[0]).into(),
        path: "path".to_string(),
        selectively_disclosable: false,
    };

    // necessary to pass db consistency checks
    claim::ActiveModel {
        id: Set(claim.id),
        credential_id: Set(credential.id),
        claim_schema_id: Set(claim_schema_ids[0]),
        value: Set(Some("value".into())),
        path: Set("path".into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        selectively_disclosable: Set(false),
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

fn dummy_claim_schema(id: ClaimSchemaId) -> ClaimSchema {
    ClaimSchema {
        id,
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    }
}
