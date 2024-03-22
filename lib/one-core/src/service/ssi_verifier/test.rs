use std::{collections::HashMap, sync::Arc, vec};

use shared_types::{DidId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    model::{
        claim_schema::ClaimSchema,
        credential_schema::{CredentialSchema, LayoutType},
        did::{Did, DidRelations},
        organisation::Organisation,
        proof::{Proof, ProofState, ProofStateEnum},
        proof_schema::{ProofInputClaimSchema, ProofInputSchema, ProofSchema},
    },
    provider::{
        credential_formatter::{
            model::{CredentialSubject, DetailCredential, Presentation},
            provider::MockCredentialFormatterProvider,
            MockCredentialFormatter,
        },
        did_method::{
            provider::{DidMethodProviderImpl, MockDidMethodProvider},
            DidMethod, MockDidMethod,
        },
        key_algorithm::provider::MockKeyAlgorithmProvider,
        revocation::provider::MockRevocationMethodProvider,
    },
    repository::{
        credential_repository::MockCredentialRepository, did_repository::MockDidRepository,
        history_repository::MockHistoryRepository, mock::proof_repository::MockProofRepository,
    },
    service::{
        error::{BusinessLogicError, ServiceError},
        ssi_verifier::SSIVerifierService,
        test_utilities::*,
    },
};

use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::revocation::{CredentialRevocationState, MockRevocationMethod};
use mockall::predicate::eq;

#[tokio::test]
async fn test_connect_to_holder_succeeds() {
    let proof_id = Uuid::new_v4();

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
                id: proof_id,
                verifier_did: Some(Did {
                    did: verifier_did_clone,
                    ..dummy_did()
                }),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),
                schema: Some(ProofSchema {
                    organisation: Some(Organisation {
                        id: Uuid::new_v4().into(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                    }),
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![ProofInputClaimSchema {
                            schema: ClaimSchema {
                                id: Uuid::new_v4().into(),
                                key: "key".to_string(),
                                data_type: "data type".to_string(),
                                created_date: OffsetDateTime::now_utc(),
                                last_modified: OffsetDateTime::now_utc(),
                            },
                            required: false,
                            order: 0,
                        }]),
                        credential_schema: Some(CredentialSchema {
                            id: Uuid::new_v4(),
                            deleted_at: None,
                            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            name: "name".to_string(),
                            format: "format".to_string(),
                            revocation_method: "format".to_string(),
                            claim_schemas: None,
                            organisation: None,
                            layout_type: LayoutType::Card,
                            layout_properties: None,
                        }),
                    }]),
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

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        ..mock_ssi_verifier_service()
    };

    let res = service.connect_to_holder(&proof_id, &None).await.unwrap();

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
        .returning(move |_, _| {
            Ok(Some(Proof {
                id: proof_id,
                verifier_did: Some(Did {
                    did: verifier_did_clone.to_owned(),
                    ..dummy_did()
                }),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Pending,
                }]),
                schema: Some(ProofSchema {
                    organisation: Some(Organisation {
                        id: Uuid::new_v4().into(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                    }),
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![ProofInputClaimSchema {
                            schema: ClaimSchema {
                                id: Uuid::new_v4().into(),
                                key: "key".to_string(),
                                data_type: "data type".to_string(),
                                created_date: OffsetDateTime::now_utc(),
                                last_modified: OffsetDateTime::now_utc(),
                            },
                            required: false,
                            order: 0,
                        }]),
                        credential_schema: Some(CredentialSchema {
                            id: Uuid::new_v4(),
                            deleted_at: None,
                            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            name: "name".to_string(),
                            format: "format".to_string(),
                            revocation_method: "format".to_string(),
                            claim_schemas: None,
                            organisation: None,
                            layout_type: LayoutType::Card,
                            layout_properties: None,
                        }),
                    }]),
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

    let mut did_repository = MockDidRepository::new();

    let did_id: DidId = Uuid::new_v4().into();

    let holder_did_value_clone = holder_did_value.clone();
    did_repository
        .expect_create_did()
        .withf(move |holder_did_value| {
            assert_eq!(&holder_did_value.did, &holder_did_value_clone.clone());
            true
        })
        .returning(move |_| Ok(did_id));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        did_repository: Arc::new(did_repository),
        did_method_provider: Arc::new(MockDidMethodProvider::default()),
        ..mock_ssi_verifier_service()
    };

    let res = service.connect_to_holder(&proof_id, &None).await.unwrap();
    assert_eq!(verifier_did, res.verifier_did);
}

#[tokio::test]
async fn test_submit_proof_succeeds() {
    let proof_id = Uuid::new_v4();
    let verifier_did = "verifier did".parse().unwrap();
    let holder_did: DidValue = "did:holder".parse().unwrap();
    let issuer_did: DidValue = "did:issuer".parse().unwrap();

    let mut proof_repository = MockProofRepository::new();

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
                id: proof_id,
                verifier_did: Some(Did {
                    did: verifier_did,
                    ..dummy_did()
                }),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Requested,
                }]),
                schema: Some(ProofSchema {
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    key: "required_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: true,
                                order: 0,
                            },
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    key: "optional_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: false,
                                order: 1,
                            },
                        ]),
                        credential_schema: Some(credential_schema),
                    }]),
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
    let issuer_did_clone = issuer_did.clone();
    formatter
        .expect_extract_credentials_unverified()
        .once()
        .returning(move |_| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
                claims: CredentialSubject {
                    values: HashMap::from([
                        ("unknown_key".to_owned(), "unknown_key_value".to_owned()),
                        ("required_key".to_owned(), "required_key_value".to_owned()),
                    ]),
                },
                status: vec![],
                credential_schema: None,
            })
        });

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
    let issuer_did_clone = issuer_did.clone();
    let holder_did_clone = holder_did.clone();
    formatter
        .expect_extract_credentials()
        .once()
        .returning(move |_, _| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
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
                status: vec![],
                credential_schema: None,
            })
        });

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .times(3)
        .returning(move |_| Some(formatter.clone()));

    proof_repository
        .expect_set_proof_holder_did()
        .once()
        .returning(|_, _| Ok(()));

    proof_repository
        .expect_set_proof_claims()
        .withf(move |set_proof_id, claims| {
            set_proof_id == &proof_id
                && claims.len() == 1
                && claims[0].value == "required_key_value"
        })
        .once()
        .returning(|_, _| Ok(()));

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_get_did_by_value()
        .once()
        .return_once({
            let holder_did = holder_did.clone();
            |_, _| {
                Ok(Some(Did {
                    did: holder_did,
                    ..dummy_did()
                }))
            }
        });
    did_repository
        .expect_get_did_by_value()
        .once()
        .with(eq(issuer_did), eq(DidRelations::default()))
        .return_once(|_, _| Ok(Some(dummy_did())));

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credential()
        .once()
        .withf(move |request| {
            let claims = request.claims.as_ref().unwrap();
            claims.len() == 1 && claims[0].value == "required_key_value"
        })
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        did_repository: Arc::new(did_repository),
        credential_repository: Arc::new(credential_repository),
        history_repository: Arc::new(history_repository),
        ..mock_ssi_verifier_service()
    };

    let presentation_content = "presentation content";
    service
        .submit_proof(proof_id, holder_did, presentation_content)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_submit_proof_failed_credential_revoked() {
    let proof_id = Uuid::new_v4();
    let verifier_did = "verifier did".parse().unwrap();
    let holder_did: DidValue = "did:holder".parse().unwrap();
    let issuer_did: DidValue = "did:issuer".parse().unwrap();

    let mut proof_repository = MockProofRepository::new();

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
                id: proof_id,
                verifier_did: Some(Did {
                    did: verifier_did,
                    ..dummy_did()
                }),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Requested,
                }]),
                schema: Some(ProofSchema {
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    key: "required_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: true,
                                order: 0,
                            },
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    key: "optional_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: false,
                                order: 1,
                            },
                        ]),
                        credential_schema: Some(credential_schema),
                    }]),
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

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_get_did_by_value()
        .once()
        .return_once(|_, _| Ok(Some(dummy_did())));

    let mut formatter = MockCredentialFormatter::new();

    let holder_did_clone = holder_did.clone();
    let issuer_did_clone = issuer_did.clone();
    formatter
        .expect_extract_credentials_unverified()
        .once()
        .returning(move |_| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
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
                status: vec![],
                credential_schema: None,
            })
        });

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
    let issuer_did_clone = issuer_did.clone();
    let holder_did_clone = holder_did.clone();
    formatter
        .expect_extract_credentials()
        .once()
        .returning(move |_, _| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
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
                status: vec![CredentialStatus {
                    id: "".to_string(),
                    r#type: "".to_string(),
                    status_purpose: None,
                    additional_fields: Default::default(),
                }],
                credential_schema: None,
            })
        });

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .times(3)
        .returning(move |_| Some(formatter.clone()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_check_credential_revocation_status()
        .once()
        .return_once(|_, _, _| Ok(CredentialRevocationState::Revoked));

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method_by_status_type()
        .once()
        .return_once(|_| Some((Arc::new(revocation_method), "".to_string())));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        revocation_method_provider: Arc::new(revocation_method_provider),
        did_repository: Arc::new(did_repository),
        ..mock_ssi_verifier_service()
    };

    let presentation_content = "presentation content";
    let err = service
        .submit_proof(proof_id, holder_did, presentation_content)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ServiceError::BusinessLogic(BusinessLogicError::CredentialIsRevokedOrSuspended)
    ));
}

#[tokio::test]
async fn test_submit_proof_failed_credential_suspended() {
    let proof_id = Uuid::new_v4();
    let verifier_did = "verifier did".parse().unwrap();
    let holder_did: DidValue = "did:holder".parse().unwrap();
    let issuer_did: DidValue = "did:issuer".parse().unwrap();

    let mut proof_repository = MockProofRepository::new();

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
                id: proof_id,
                verifier_did: Some(Did {
                    did: verifier_did,
                    ..dummy_did()
                }),
                state: Some(vec![ProofState {
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    state: ProofStateEnum::Requested,
                }]),
                schema: Some(ProofSchema {
                    input_schemas: Some(vec![ProofInputSchema {
                        validity_constraint: None,
                        claim_schemas: Some(vec![
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    key: "required_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: true,
                                order: 0,
                            },
                            ProofInputClaimSchema {
                                schema: ClaimSchema {
                                    key: "optional_key".to_string(),
                                    ..dummy_claim_schema()
                                },
                                required: false,
                                order: 1,
                            },
                        ]),
                        credential_schema: Some(credential_schema),
                    }]),
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

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_get_did_by_value()
        .once()
        .return_once(|_, _| Ok(Some(dummy_did())));

    let mut formatter = MockCredentialFormatter::new();

    let holder_did_clone = holder_did.clone();
    let issuer_did_clone = issuer_did.clone();
    formatter
        .expect_extract_credentials_unverified()
        .once()
        .returning(move |_| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
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
                status: vec![],
                credential_schema: None,
            })
        });

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
    let issuer_did_clone = issuer_did.clone();
    let holder_did_clone = holder_did.clone();
    formatter
        .expect_extract_credentials()
        .once()
        .returning(move |_, _| {
            Ok(DetailCredential {
                id: None,
                issued_at: Some(OffsetDateTime::now_utc()),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::days(10)),
                invalid_before: Some(OffsetDateTime::now_utc()),
                issuer_did: Some(issuer_did_clone.to_owned()),
                subject: Some(holder_did_clone.to_owned()),
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
                status: vec![CredentialStatus {
                    id: "".to_string(),
                    r#type: "".to_string(),
                    status_purpose: None,
                    additional_fields: Default::default(),
                }],
                credential_schema: None,
            })
        });

    let formatter = Arc::new(formatter);
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .times(3)
        .returning(move |_| Some(formatter.clone()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_check_credential_revocation_status()
        .once()
        .return_once(|_, _, _| {
            Ok(CredentialRevocationState::Suspended {
                suspend_end_date: None,
            })
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method_by_status_type()
        .once()
        .return_once(|_| Some((Arc::new(revocation_method), "".to_string())));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        formatter_provider: Arc::new(formatter_provider),
        revocation_method_provider: Arc::new(revocation_method_provider),
        did_repository: Arc::new(did_repository),
        ..mock_ssi_verifier_service()
    };

    let presentation_content = "presentation content";
    let err = service
        .submit_proof(proof_id, holder_did, presentation_content)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ServiceError::BusinessLogic(BusinessLogicError::CredentialIsRevokedOrSuspended)
    ));
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
                    state: ProofStateEnum::Requested,
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

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIVerifierService {
        proof_repository: Arc::new(proof_repository),
        history_repository: Arc::new(history_repository),
        ..mock_ssi_verifier_service()
    };

    service.reject_proof(&proof_id).await.unwrap();
}

fn mock_ssi_verifier_service() -> SSIVerifierService {
    let did_method = MockDidMethod::new();
    let mut did_methods: HashMap<String, Arc<dyn DidMethod>> = HashMap::new();
    did_methods.insert("INTERNAL".to_string(), Arc::new(did_method));
    let did_method_provider = DidMethodProviderImpl::new(did_methods);

    SSIVerifierService {
        did_repository: Arc::new(MockDidRepository::new()),
        formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
        proof_repository: Arc::new(MockProofRepository::new()),
        credential_repository: Arc::new(MockCredentialRepository::new()),
        did_method_provider: Arc::new(did_method_provider),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::new()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        history_repository: Arc::new(MockHistoryRepository::new()),
        config: Arc::new(generic_config().core),
    }
}
