use super::ProofService;
use crate::{
    model::{
        claim::ClaimRelations,
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        did::{Did, DidRelations, DidType, DidValue},
        organisation::{Organisation, OrganisationRelations},
        proof::{
            GetProofList, Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
        },
        proof_schema::{
            ProofSchema, ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaRelations,
        },
    },
    repository::{
        error::DataLayerError,
        mock::{
            claim_schema_repository::MockClaimSchemaRepository, did_repository::MockDidRepository,
            proof_repository::MockProofRepository,
            proof_schema_repository::MockProofSchemaRepository,
        },
    },
    service::{
        credential_schema::dto::ClaimSchemaId,
        did::dto::DidId,
        error::ServiceError,
        proof::dto::{
            CreateProofClaimRequestDTO, CreateProofRequestDTO, GetProofQueryDTO, ProofId,
        },
    },
};
use mockall::{predicate::*, Sequence};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Default)]
struct Repositories {
    pub proof_schema_repository: MockProofSchemaRepository,
    pub proof_repository: MockProofRepository,
    pub claim_schema_repository: MockClaimSchemaRepository,
    pub did_repository: MockDidRepository,
}

fn setup_service(repositories: Repositories) -> ProofService {
    ProofService::new(
        Arc::new(repositories.claim_schema_repository),
        Arc::new(repositories.proof_repository),
        Arc::new(repositories.proof_schema_repository),
        Arc::new(repositories.did_repository),
    )
}

fn construct_proof_with_state(proof_id: &ProofId, state: ProofStateEnum) -> Proof {
    Proof {
        id: proof_id.to_owned(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "transport".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state,
        }]),
        schema: None,
        claims: None,
        verifier_did: Some(Did {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            organisation_id: Uuid::new_v4(),
            did: "did".to_string(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
        }),
        holder_did: None,
    }
}

#[tokio::test]
async fn test_get_proof_exists() {
    let mut proof_repository = MockProofRepository::default();

    let proof = Proof {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "transport".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        schema: Some(ProofSchema {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
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
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            organisation_id: Uuid::new_v4(),
            did: "did".to_string(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
        }),
        holder_did: None,
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
                    holder_did: Some(DidRelations::default()),
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
        transport: "transport".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        schema: Some(ProofSchema {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "proof schema".to_string(),
            expire_duration: 0,
            claim_schemas: None,
            organisation: None,
        }),
        claims: None,
        verifier_did: Some(Did {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            organisation_id: Uuid::new_v4(),
            did: "did".to_string(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
        }),
        holder_did: None,
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
    let transport = "transport".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4(),
        verifier_did_id: Uuid::new_v4(),
        transport: transport.to_owned(),
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
                name: "proof schema".to_string(),
                expire_duration: 0,
                claim_schemas: None,
                organisation: None,
            })
        });

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .times(1)
        .withf(move |id, _| &request.verifier_did_id == id)
        .returning(|id, _| {
            Ok(Did {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                organisation_id: Uuid::new_v4(),
                did: "did".to_string(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
            })
        });

    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .times(1)
        .withf(move |proof| proof.transport == transport)
        .returning(move |_| Ok(proof_id));

    let service = setup_service(Repositories {
        proof_repository,
        did_repository,
        proof_schema_repository,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), proof_id);
}

#[tokio::test]
async fn test_share_proof_created_success() {
    let proof_id = ProofId::new_v4();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Created);

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
        ..Default::default()
    });

    let base_url = "base_url";
    let result = service.share_proof(&proof_id, base_url).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(
        result.url,
        format!(
            "{base_url}/ssi/temporary-verifier/v1/connect?protocol={}&proof={proof_id}",
            proof.transport
        )
    );
}

#[tokio::test]
async fn test_share_proof_pending_success() {
    let proof_id = ProofId::new_v4();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Pending);

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
        ..Default::default()
    });

    let base_url = "base_url";
    let result = service.share_proof(&proof_id, base_url).await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(
        result.url,
        format!(
            "{base_url}/ssi/temporary-verifier/v1/connect?protocol={}&proof={proof_id}",
            proof.transport
        )
    );
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

    let result = service.share_proof(&proof_id, "base_url").await;
    assert!(matches!(result, Err(ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_set_holder_connected_did_already_exists() {
    let did_value: DidValue = "did:value".to_string();
    let did_id = DidId::new_v4();
    let mut did_repository = MockDidRepository::default();
    {
        let value_clone = did_value.clone();
        did_repository
            .expect_get_did_by_value()
            .times(1)
            .withf(move |value, _| &value_clone == value)
            .returning(move |value, _| {
                Ok(Did {
                    id: did_id.to_owned(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "did".to_string(),
                    organisation_id: Uuid::new_v4(),
                    did: value.to_owned(),
                    did_type: DidType::Local,
                    did_method: "KEY".to_string(),
                })
            });
    }

    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(move |_, _| {
            Ok(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Pending,
            ))
        });

    proof_repository
        .expect_set_proof_holder_did()
        .times(1)
        .withf(move |id, did| &proof_id == id && did.id == did_id)
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_state()
        .times(1)
        .withf(move |id, state| &proof_id == id && state.state == ProofStateEnum::Offered)
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        did_repository,
        ..Default::default()
    });

    let result = service.set_holder_connected(&proof_id, &did_value).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_set_holder_connected_did_unknown() {
    let did_value: DidValue = "did:value".to_string();
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did_by_value()
        .times(1)
        .returning(|_, _| Err(DataLayerError::RecordNotFound));

    {
        let value_clone = did_value.clone();
        did_repository
            .expect_create_did()
            .times(1)
            .withf(move |did| did.did == value_clone)
            .returning(|did| Ok(did.id));
    }

    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(move |_, _| {
            Ok(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Pending,
            ))
        });

    proof_repository
        .expect_set_proof_holder_did()
        .times(1)
        .withf(move |id, _| &proof_id == id)
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_state()
        .times(1)
        .withf(move |id, state| &proof_id == id && state.state == ProofStateEnum::Offered)
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        did_repository,
        ..Default::default()
    });

    let result = service.set_holder_connected(&proof_id, &did_value).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_set_holder_connected_invalid_state() {
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

    let did_value: DidValue = "did:value".to_string();
    let result = service.set_holder_connected(&proof_id, &did_value).await;
    assert!(matches!(result, Err(ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_accept_proof_success() {
    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(move |_, _| {
            Ok(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Offered,
            ))
        });

    let proved_claims: Vec<CreateProofClaimRequestDTO> = vec![
        CreateProofClaimRequestDTO {
            claim_schema_id: ClaimSchemaId::new_v4(),
            value: "value1".to_string(),
        },
        CreateProofClaimRequestDTO {
            claim_schema_id: ClaimSchemaId::new_v4(),
            value: "value2".to_string(),
        },
    ];

    let claim_schema_ids: Vec<ClaimSchemaId> = proved_claims
        .iter()
        .map(|claim| claim.claim_schema_id)
        .collect();
    let mut claim_schema_repository = MockClaimSchemaRepository::default();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .times(1)
        .withf(move |ids, _| &claim_schema_ids == ids)
        .returning(|ids, _| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                })
                .collect())
        });

    proof_repository
        .expect_set_proof_claims()
        .times(1)
        .withf(move |id, claims| &proof_id == id && claims.len() == 2)
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_state()
        .times(1)
        .withf(move |id, state| &proof_id == id && state.state == ProofStateEnum::Accepted)
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        claim_schema_repository,
        ..Default::default()
    });

    let result = service.accept_proof(&proof_id, proved_claims).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_accept_proof_invalid_state() {
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

    let result = service
        .accept_proof(
            &proof_id,
            vec![CreateProofClaimRequestDTO {
                claim_schema_id: ClaimSchemaId::new_v4(),
                value: "value".to_string(),
            }],
        )
        .await;
    assert!(matches!(result, Err(ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_reject_proof_success() {
    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(move |_, _| {
            Ok(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Offered,
            ))
        });

    proof_repository
        .expect_set_proof_state()
        .times(1)
        .withf(move |id, state| &proof_id == id && state.state == ProofStateEnum::Rejected)
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.reject_proof(&proof_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_reject_proof_invalid_state() {
    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(move |_, _| {
            Ok(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Accepted,
            ))
        });

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.reject_proof(&proof_id).await;
    assert!(matches!(result, Err(ServiceError::AlreadyExists)));
}

#[tokio::test]
async fn test_fail_proof() {
    let proof_id = ProofId::new_v4();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_set_proof_state()
        .times(1)
        .withf(move |id, state| &proof_id == id && state.state == ProofStateEnum::Error)
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.fail_proof(&proof_id).await;
    assert!(result.is_ok());
}
