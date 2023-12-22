use std::sync::Arc;

use mockall::{predicate::*, Sequence};
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofService;
use crate::config::core_config::CoreConfig;
use crate::provider::transport_protocol::provider::MockTransportProtocolProvider;
use crate::provider::transport_protocol::MockTransportProtocol;
use crate::service::error::BusinessLogicError;
use crate::service::test_utilities::generic_config;
use crate::{
    model::{
        claim::ClaimRelations,
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        did::{Did, DidRelations, DidType},
        interaction::InteractionRelations,
        organisation::{Organisation, OrganisationRelations},
        proof::{
            GetProofList, Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
        },
        proof_schema::{
            ProofSchema, ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaRelations,
        },
    },
    repository::{
        credential_repository::MockCredentialRepository,
        did_repository::MockDidRepository,
        error::DataLayerError,
        interaction_repository::MockInteractionRepository,
        mock::{
            proof_repository::MockProofRepository,
            proof_schema_repository::MockProofSchemaRepository,
        },
    },
    service::{
        error::ServiceError,
        proof::dto::{CreateProofRequestDTO, GetProofQueryDTO, ProofId},
    },
};

#[derive(Default)]
struct Repositories {
    pub proof_schema_repository: MockProofSchemaRepository,
    pub proof_repository: MockProofRepository,
    pub did_repository: MockDidRepository,
    pub interaction_repository: MockInteractionRepository,
    pub credential_repository: MockCredentialRepository,
    pub protocol_provider: MockTransportProtocolProvider,
    pub config: CoreConfig,
}

fn setup_service(repositories: Repositories) -> ProofService {
    ProofService::new(
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.proof_repository),
        Arc::new(repositories.proof_schema_repository),
        Arc::new(repositories.did_repository),
        Arc::new(repositories.interaction_repository),
        Arc::new(repositories.protocol_provider),
        Arc::new(repositories.config),
    )
}

fn construct_proof_with_state(proof_id: &ProofId, state: ProofStateEnum) -> Proof {
    Proof {
        id: proof_id.to_owned(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state,
        }]),
        schema: None,
        claims: None,
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            organisation: Some(Organisation {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        interaction: None,
    }
}

#[tokio::test]
async fn test_get_presentation_definition_holder_did_not_local() {
    let mut proof_repository = MockProofRepository::default();

    let proof = Proof {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Pending,
        }]),
        redirect_uri: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "proof schema".to_string(),
            expire_duration: 0,
            claim_schemas: Some(vec![ProofSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4(),
                    key: "key_123".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: true,
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "credential schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    organisation: None,
                }),
            }]),
            organisation: Some(Organisation {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
        }),
        claims: Some(vec![]),
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        interaction: None,
    };

    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .times(1)
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                }),
            )
            .returning(move |_, _| Ok(res_clone.clone()));
    }

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.get_proof_presentation_definition(&proof.id).await;

    assert!(result.is_err_and(|e| matches!(e, ServiceError::IncorrectParameters)));
}

#[tokio::test]
async fn test_get_proof_exists() {
    let mut proof_repository = MockProofRepository::default();

    let proof = Proof {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            claim_schemas: Some(vec![ProofSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4(),
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: true,
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "credential schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    organisation: None,
                }),
            }]),
            organisation: Some(Organisation {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
        }),
        claims: Some(vec![]),
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        interaction: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .times(1)
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(res_clone.clone()));
    }

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, proof.id);
    assert_eq!(result.transport, proof.transport);
}

#[tokio::test]
async fn test_get_proof_missing() {
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(|_, _| Err(DataLayerError::RecordNotFound));

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.get_proof(&Uuid::new_v4()).await;
    assert!(matches!(result, Err(ServiceError::NotFound)));
}

#[tokio::test]
async fn test_get_proof_list_success() {
    let mut proof_repository = MockProofRepository::default();

    let proof = Proof {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        schema: Some(ProofSchema {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            claim_schemas: None,
            organisation: None,
        }),
        claims: None,
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        interaction: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof_list()
            .times(1)
            .returning(move |_| {
                Ok(GetProofList {
                    values: vec![res_clone.to_owned()],
                    total_pages: 1,
                    total_items: 1,
                })
            });
    }

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service
        .get_proof_list(GetProofQueryDTO {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            exact: None,
            name: None,
            organisation_id: Uuid::new_v4().to_string(),
        })
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 1);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 1);
    let result = &result.values[0];
    assert_eq!(result.id, proof.id);
}

#[tokio::test]
async fn test_create_proof() {
    let transport = "PROCIVIS_TEMPORARY".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4(),
        verifier_did_id: Uuid::new_v4().into(),
        transport: transport.to_owned(),
        redirect_uri: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                claim_schemas: None,
                organisation: None,
            })
        });

    let request_clone = request.clone();
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .times(1)
        .withf(move |id, _| &request_clone.verifier_did_id == id)
        .returning(|id, _| {
            Ok(Some(Did {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
            }))
        });

    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .times(1)
        .withf(move |proof| proof.transport == transport)
        .returning(move |_| Ok(proof_id));

    let interaction_repository = MockInteractionRepository::default();
    let credential_repository = MockCredentialRepository::default();

    let service = setup_service(Repositories {
        credential_repository,
        proof_repository,
        did_repository,
        proof_schema_repository,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert_eq!(result.unwrap(), proof_id);
}

#[tokio::test]
async fn test_create_proof_did_deactivated_error() {
    let transport = "PROCIVIS_TEMPORARY".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4(),
        verifier_did_id: Uuid::new_v4().into(),
        transport: transport.to_owned(),
        redirect_uri: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                claim_schemas: None,
                organisation: None,
            })
        });

    let request_clone = request.clone();
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .once()
        .withf(move |id, _| &request_clone.verifier_did_id == id)
        .returning(|id, _| {
            Ok(Some(Did {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: true,
            }))
        });

    let service = setup_service(Repositories {
        did_repository,
        proof_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert2::assert!(
        let Err(
            ServiceError::BusinessLogic(
                BusinessLogicError::DidIsDeactivated(_)
            )
        ) = result
    );
}

#[tokio::test]
async fn test_create_proof_schema_deleted() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .returning(|id, _| {
            Ok(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: Some(OffsetDateTime::now_utc()),
                name: "proof schema".to_string(),
                expire_duration: 0,
                claim_schemas: None,
                organisation: None,
            })
        });

    let service = setup_service(Repositories {
        proof_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_proof(CreateProofRequestDTO {
            proof_schema_id: Uuid::new_v4(),
            verifier_did_id: Uuid::new_v4().into(),
            transport: "PROCIVIS_TEMPORARY".to_string(),
            redirect_uri: None,
        })
        .await;
    assert!(matches!(result, Err(ServiceError::NotFound)));
}

#[tokio::test]
async fn test_share_proof_created_success() {
    let proof_id = ProofId::new_v4();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Created);
    let mut protocol = MockTransportProtocol::default();
    let mut protocol_provider = MockTransportProtocolProvider::default();

    let expected_url = "test_url";
    protocol
        .expect_share_proof()
        .times(1)
        .returning(|_| Ok(expected_url.to_owned()));

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .times(1)
        .returning(move |_| Ok(protocol.clone()));

    let mut seq = Sequence::new();
    let mut proof_repository = MockProofRepository::default();
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .times(1)
            .in_sequence(&mut seq)
            .withf(move |id, relations| {
                id == &proof_id
                    && relations
                        == &ProofRelations {
                            state: Some(ProofStateRelations::default()),
                            ..Default::default()
                        }
            })
            .returning(move |_, _| Ok(res_clone.to_owned()));
    }

    proof_repository
        .expect_set_proof_state()
        .times(1)
        .in_sequence(&mut seq)
        .withf(move |id, state| id == &proof_id && state.state == ProofStateEnum::Pending)
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_proof(&proof_id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.url, expected_url);
}

#[tokio::test]
async fn test_share_proof_pending_success() {
    let proof_id = ProofId::new_v4();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Pending);
    let mut protocol = MockTransportProtocol::default();
    let mut protocol_provider = MockTransportProtocolProvider::default();

    let expected_url = "test_url";
    protocol
        .expect_share_proof()
        .times(1)
        .returning(|_| Ok(expected_url.to_owned()));

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .times(1)
        .returning(move |_| Ok(protocol.clone()));

    let mut proof_repository = MockProofRepository::default();
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .times(1)
            .withf(move |id, relations| {
                id == &proof_id
                    && relations
                        == &ProofRelations {
                            state: Some(ProofStateRelations::default()),
                            ..Default::default()
                        }
            })
            .returning(move |_, _| Ok(res_clone.to_owned()));
    }

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_proof(&proof_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_share_proof_invalid_state() {
    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(move |_, _| {
            Ok(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Rejected,
            ))
        });

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.share_proof(&proof_id).await;
    assert!(matches!(result, Err(ServiceError::AlreadyShared)));
}
