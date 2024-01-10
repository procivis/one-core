use std::{collections::HashMap, sync::Arc, vec};

use shared_types::{DidId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    model::{
        claim_schema::ClaimSchema,
        credential_schema::CredentialSchema,
        did::{Did, DidType},
        organisation::Organisation,
        proof::{Proof, ProofState, ProofStateEnum},
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    provider::{
        credential_formatter::{
            model::{CredentialSubject, DetailCredential, Presentation},
            provider::MockCredentialFormatterProvider,
            MockCredentialFormatter,
        },
        did_method::{
            dto::{DidDocumentDTO, DidVerificationMethodDTO},
            provider::{DidMethodProviderImpl, MockDidMethodProvider},
            DidMethod, MockDidMethod,
        },
        key_algorithm::provider::MockKeyAlgorithmProvider,
        revocation::provider::MockRevocationMethodProvider,
    },
    repository::{
        did_repository::MockDidRepository,
        mock::{
            claim_repository::MockClaimRepository,
            claim_schema_repository::MockClaimSchemaRepository,
            proof_repository::MockProofRepository,
        },
    },
    service::{
        ssi_verifier::SSIVerifierService,
        test_utilities::{dummy_proof, generic_config},
    },
};

use mockall::predicate::eq;

#[tokio::test]
async fn test_connect_to_holder_succeeds() {
    let proof_id = Uuid::new_v4();
    let holder_did_value: DidValue = "holder did value".parse().unwrap();

    let verifier_did: DidValue = "verifier did".parse().unwrap();

    let verifier_did_clone = verifier_did.clone();
    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                verifier_did: Some(Did {
                    did: verifier_did_clone,
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
            }))
        });

    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                holder_did: Some(dummy_did()),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),

                ..dummy_proof()
            }))
        });

    proof_repository
        .expect_set_proof_state()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let did_id: DidId = Uuid::new_v4().into();

    let holder_did_value_clone = holder_did_value.clone();

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_get_did_by_value()
        .withf(move |_holder_did_value, _| {
            assert_eq!(_holder_did_value, &holder_did_value_clone.clone());
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Did {
                id: did_id,
                ..dummy_did()
            }))
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
        .connect_to_holder(&proof_id, &holder_did_value, &None)
        .await
        .unwrap();

    assert_eq!(verifier_did, res.verifier_did);
}

#[tokio::test]
async fn test_connect_to_holder_succeeds_new_did() {
    let proof_id = Uuid::new_v4();
    let holder_did_value: DidValue = "did:internal:key".parse().unwrap();

    let verifier_did: DidValue = "verifier did".parse().unwrap();

    let verifier_did_clone = verifier_did.clone();
    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                verifier_did: Some(Did {
                    did: verifier_did_clone,
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
            }))
        });

    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Proof {
                holder_did: Some(dummy_did()),
                verifier_did: Some(dummy_did()),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),

                ..dummy_proof()
            }))
        });

    proof_repository
        .expect_set_proof_state()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let holder_did_value_clone = holder_did_value.clone();
    let mut did_method_provider = MockDidMethodProvider::default();
    did_method_provider
        .expect_resolve()
        .once()
        .with(eq(holder_did_value.clone()))
        .return_once(move |_| {
            Ok(DidDocumentDTO {
                context: vec![],
                id: holder_did_value_clone,
                verification_method: vec![DidVerificationMethodDTO {
                    id: "id".to_string(),
                    r#type: "type".to_string(),
                    controller: "controller".to_string(),
                    public_key_jwk: crate::provider::did_method::dto::PublicKeyJwkDTO::Ec(
                        crate::provider::did_method::dto::PublicKeyJwkEllipticDataDTO {
                            r#use: None,
                            crv: "P-256".to_string(),
                            x: "123".to_string(),
                            y: Some("123".to_string()),
                        },
                    ),
                }],
                authentication: None,
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
            })
        });

    let holder_did_value_clone = holder_did_value.clone();

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_get_did_by_value()
        .withf(move |_holder_did_value, _| {
            assert_eq!(_holder_did_value, &holder_did_value_clone.clone());
            true
        })
        .once()
        .returning(|_, _| Ok(None));

    let did_id: DidId = Uuid::new_v4().into();

    let holder_did_value_clone = holder_did_value.clone();
    did_repository
        .expect_create_did()
        .withf(move |holder_did_value| {
            assert_eq!(&holder_did_value.did, &holder_did_value_clone.clone());
            true
        })
        .returning(move |_| Ok(did_id));

    proof_repository
        .expect_set_proof_holder_did()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .returning(|_, _| Ok(()));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        did_repository: Arc::new(did_repository),
        did_method_provider: Arc::new(did_method_provider),
        ..mock_ssi_verifier_service()
    };

    let res = service
        .connect_to_holder(&proof_id, &holder_did_value, &None)
        .await
        .unwrap();

    assert_eq!(verifier_did, res.verifier_did);
}

#[tokio::test]
async fn test_submit_proof_succeeds() {
    let proof_id = Uuid::new_v4();
    let verifier_did = "verifier did".parse().unwrap();
    let holder_did: DidValue = "did:key:zDnaenbFCJgNyzfAfHmVrS8omec4Fthtipt32bswEnUwtbPot"
        .parse()
        .unwrap();

    let mut proof_repository = MockProofRepository::new();

    let holder_did_clone = holder_did.clone();
    proof_repository
        .expect_get_proof()
        .withf(move |_proof_id, _| {
            assert_eq!(_proof_id, &proof_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            let credential_schema = dummy_credential_schema();
            Ok(Some(Proof {
                verifier_did: Some(Did {
                    did: verifier_did,
                    ..dummy_did()
                }),
                holder_did: Some(Did {
                    did: holder_did_clone,
                    ..dummy_did()
                }),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Offered,
                }]),
                schema: Some(ProofSchema {
                    claim_schemas: Some(vec![
                        ProofSchemaClaim {
                            schema: ClaimSchema {
                                key: "required_key".to_string(),
                                ..dummy_claim_schema()
                            },
                            required: true,
                            credential_schema: Some(credential_schema.to_owned()),
                        },
                        ProofSchemaClaim {
                            schema: ClaimSchema {
                                key: "optional_key".to_string(),
                                ..dummy_claim_schema()
                            },
                            required: false,
                            credential_schema: Some(credential_schema),
                        },
                    ]),
                    ..dummy_proof_schema()
                }),
                ..dummy_proof()
            }))
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

    let holder_did_clone = holder_did.clone();
    formatter
        .expect_extract_presentation()
        .once()
        .returning(move |_, _| {
            Ok(Presentation {
                id: Some("presentation id".to_string()),
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                issuer_did: Some(holder_did_clone.to_owned()),
                nonce: None,
                credentials: vec!["credential".to_string()],
            })
        });
    formatter.expect_get_leeway().returning(|| 10);
    formatter
        .expect_extract_credentials()
        .once()
        .returning(move |_, _| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: None,
                subject: Some(holder_did.to_string()),
                claims: CredentialSubject {
                    // submitted claims
                    values: HashMap::from([
                        // ignored by verifier
                        ("unknown_key".to_owned(), "unknown_key_value".to_owned()),
                        // required by verifier
                        ("required_key".to_owned(), "required_key_value".to_owned()),
                        // optional
                        // ("optional_key".to_owned(), "optional_key_value".to_owned()),
                    ]),
                },
                status: None,
            })
        });

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .times(2)
        .returning(move |_| Some(formatter.clone()));

    let mut claim_schema_repository = MockClaimSchemaRepository::new();
    claim_schema_repository
        .expect_get_claim_schema_list()
        .once()
        .withf(|ids, _| ids.len() == 1)
        .return_once(|ids, _| {
            Ok(ids
                .into_iter()
                .map(|id| ClaimSchema {
                    id,
                    ..dummy_claim_schema()
                })
                .collect())
        });

    proof_repository
        .expect_set_proof_claims()
        .withf(move |set_proof_id, claims| {
            set_proof_id == &proof_id
                && claims.len() == 1
                && claims[0].value == "required_key_value"
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut claim_repository = MockClaimRepository::new();
    claim_repository
        .expect_create_claim_list()
        .once()
        .withf(|claims| claims.len() == 1 && claims[0].value == "required_key_value")
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
            Ok(Some(Proof {
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Offered,
                }]),
                ..dummy_proof()
            }))
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
    let did_method = MockDidMethod::new();
    let mut did_methods: HashMap<String, Arc<dyn DidMethod + Send + Sync>> = HashMap::new();
    did_methods.insert("INTERNAL".to_string(), Arc::new(did_method));
    let did_method_provider = DidMethodProviderImpl::new(did_methods);

    SSIVerifierService {
        did_repository: Arc::new(MockDidRepository::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        claim_schema_repository: Arc::new(MockClaimSchemaRepository::new()),
        proof_repository: Arc::new(MockProofRepository::new()),
        claim_repository: Arc::new(MockClaimRepository::new()),
        did_method_provider: Arc::new(did_method_provider),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::new()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        config: Arc::new(generic_config().core),
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
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "INTERNAL".to_string(),
        keys: None,
        organisation: Some(dummy_organisation()),
        deactivated: false,
    }
}

fn dummy_organisation() -> Organisation {
    Organisation {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    }
}

fn dummy_credential_schema() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        format: "format".to_string(),
        revocation_method: "format".to_string(),
        claim_schemas: None,
        organisation: None,
    }
}

fn dummy_claim_schema() -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4(),
        key: "key".to_string(),
        data_type: "data type".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    }
}
