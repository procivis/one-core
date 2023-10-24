use std::{sync::Arc, vec};

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    config::data_structure::CoreConfig,
    model::{
        claim_schema::ClaimSchema,
        credential_schema::CredentialSchema,
        did::{Did, DidType},
        proof::{Proof, ProofState, ProofStateEnum},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    provider::credential_formatter::{
        model::CredentialPresentation, provider::MockCredentialFormatterProvider,
        MockCredentialFormatter,
    },
    repository::mock::{
        claim_repository::MockClaimRepository, claim_schema_repository::MockClaimSchemaRepository,
        did_repository::MockDidRepository, proof_repository::MockProofRepository,
    },
    service::ssi_verifier::SSIVerifierService,
};

#[tokio::test]
async fn test_connect_to_holder_succeeds() {
    let proof_id = Uuid::new_v4();
    let holder_did_value = "holder did value";

    let verifier_did = "verifier did";
    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(|_, _| {
            Ok(Proof {
                verifier_did: Some(Did {
                    did: verifier_did.to_string(),
                    ..dummy_did()
                }),
                schema: Some(ProofSchema {
                    claim_schemas: Some(vec![ProofSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4(),
                            key: "key".to_string(),
                            data_type: "data type".to_string(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                        },
                        required: false,
                        credential_schema: Some(CredentialSchema {
                            id: Uuid::new_v4(),
                            deleted_at: None,
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            name: "name".to_string(),
                            format: "format".to_string(),
                            revocation_method: "format".to_string(),
                            claim_schemas: None,
                            organisation: None,
                        }),
                    }]),
                    ..dummy_proof_schema()
                }),
                ..dummy_proof()
            })
        });

    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Proof {
                holder_did: Some(dummy_did()),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),

                ..dummy_proof()
            })
        });

    proof_repository
        .expect_set_proof_state()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let did_id = Uuid::new_v4();
    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_get_did_by_value()
        .withf(move |_holder_did_value, _| {
            assert_eq!(_holder_did_value, &holder_did_value);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Did {
                id: did_id,
                ..dummy_did()
            })
        });

    proof_repository
        .expect_set_proof_holder_did()
        .withf(move |_proof_id, did| {
            assert_eq!(_proof_id, &proof_id);
            assert_eq!(did.id, did_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        did_repository: Arc::new(did_repository),
        ..mock_ssi_verifier_service()
    };

    let res = service
        .connect_to_holder(&proof_id, &holder_did_value.to_string())
        .await
        .unwrap();

    assert_eq!(verifier_did, res.verifier_did);
}

#[tokio::test]
async fn test_submit_proof_succeeds() {
    let proof_id = Uuid::new_v4();
    let verifier_did = "verifier did";

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Proof {
                verifier_did: Some(Did {
                    did: verifier_did.to_string(),
                    ..dummy_did()
                }),
                holder_did: Some(dummy_did()),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Offered,
                }]),
                schema: Some(ProofSchema {
                    claim_schemas: Some(vec![ProofSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4(),
                            key: "key".to_string(),
                            data_type: "data type".to_string(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                        },
                        required: false,
                        credential_schema: Some(CredentialSchema {
                            id: Uuid::new_v4(),
                            deleted_at: None,
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            name: "name".to_string(),
                            format: "format".to_string(),
                            revocation_method: "format".to_string(),
                            claim_schemas: None,
                            organisation: None,
                        }),
                    }]),
                    ..dummy_proof_schema()
                }),
                ..dummy_proof()
            })
        });

    proof_repository
        .expect_set_proof_state()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_extract_presentation()
        .once()
        .returning(|_, _| {
            Ok(CredentialPresentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer_did: Some("issuer did".to_string()),
                credentials: vec![],
            })
        });
    formatter.expect_get_leeway().returning(|| 10);

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .withf(|formatter_id| {
            assert_eq!(formatter_id, "format");
            true
        })
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut claim_schema_repository = MockClaimSchemaRepository::new();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .once()
        .return_once(move |_, _| {
            Ok(vec![ClaimSchema {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                key: "claim schema key".to_string(),
                data_type: "claim data type".to_string(),
            }])
        });

    proof_repository
        .expect_set_proof_claims()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut claim_repository = MockClaimRepository::new();
    claim_repository
        .expect_create_claim_list()
        .once()
        .returning(|_| Ok(()));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        claim_schema_repository: Arc::new(claim_schema_repository),
        formatter_provider: Arc::new(formatter_provider),
        claim_repository: Arc::new(claim_repository),
        ..mock_ssi_verifier_service()
    };

    let presentation_content = "presentation content";
    service
        .submit_proof(&proof_id, presentation_content)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reject_proof_succeeds() {
    let proof_id = Uuid::new_v4();

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Proof {
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Offered,
                }]),
                ..dummy_proof()
            })
        });

    proof_repository
        .expect_set_proof_state()
        .withf(move |_proof_id, proof_state| {
            assert_eq!(_proof_id, &proof_id);
            assert_eq!(ProofStateEnum::Rejected, proof_state.state);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        ..mock_ssi_verifier_service()
    };

    service.reject_proof(&proof_id).await.unwrap();
}

fn mock_ssi_verifier_service() -> SSIVerifierService {
    SSIVerifierService {
        did_repository: Arc::new(MockDidRepository::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        claim_schema_repository: Arc::new(MockClaimSchemaRepository::new()),
        proof_repository: Arc::new(MockProofRepository::new()),
        claim_repository: Arc::new(MockClaimRepository::new()),
        config: Arc::new(CoreConfig {
            format: Default::default(),
            exchange: Default::default(),
            transport: Default::default(),
            revocation: Default::default(),
            did: Default::default(),
            datatype: Default::default(),
            key_algorithm: Default::default(),
            key_storage: Default::default(),
        }),
    }
}

fn dummy_proof() -> Proof {
    Proof {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        transport: "protocol".to_string(),
        state: None,
        schema: None,
        claims: None,
        verifier_did: None,
        holder_did: None,
        interaction: None,
    }
}

fn dummy_proof_schema() -> ProofSchema {
    ProofSchema {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        name: "Proof schema".to_string(),
        expire_duration: 100,
        claim_schemas: None,
        organisation: None,
    }
}

fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did".to_string(),
        did_type: DidType::Local,
        did_method: "John".to_string(),
        keys: None,
        organisation: None,
    }
}
